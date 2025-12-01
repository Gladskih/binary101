"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { parseVorbisCodecPrivate } from "../../analyzers/webm/codecprivate.js";

const buildDataView = (bytes: number[]): DataView => new DataView(new Uint8Array(bytes).buffer);

void test("parseVorbisCodecPrivate reads packet sizes and vendor", () => {
  // Vorbis CodecPrivate layout:
  // 0x02, sizes for packets 1 and 2 using lacing, then packet 1 (id), packet 2 (comment), packet 3 (setup)
  // Here: id=3 bytes (dummy), comment has vendor length 3 with string "abc", setup has 2 bytes (dummy)
  const header = [0x02, 0x03, 0x12];
  const idPacket = [0x01, 0x02, 0x03];
  const commentHeader = [0x03, 0x76, 0x6f, 0x72, 0x62, 0x69, 0x73]; // packet type + "vorbis"
  const vendorLength = [0x03, 0x00, 0x00, 0x00]; // 3, little-endian
  const vendor = [0x61, 0x62, 0x63]; // "abc"
  const userCommentListLength = [0x00, 0x00, 0x00, 0x00]; // 0 comments (rest ignored)
  const commentPacket = [...commentHeader, ...vendorLength, ...vendor, ...userCommentListLength];
  const setupPacket = [0xaa, 0xbb];
  const bytes = [...header, ...idPacket, ...commentPacket, ...setupPacket];
  const dv = buildDataView(bytes);
  const issues: string[] = [];

  const result = parseVorbisCodecPrivate(dv, 0, bytes.length, issues);

  assert.deepEqual(result.headerPacketLengths, [3, commentPacket.length, 2]);
  assert.equal(result.vendor, "abc");
  assert.equal(result.truncated, false);
  assert.deepEqual(issues, []);
});

void test("parseVorbisCodecPrivate handles truncation and bad signature", () => {
  // missing vorbis signature and truncated vendor length
  const header = [0x02, 0x01, 0x05];
  const idPacket = [0x01];
  const badCommentPacket = [0x03, 0x00, 0x00]; // too short and no "vorbis"
  const bytes = [...header, ...idPacket, ...badCommentPacket];
  const dv = buildDataView(bytes);
  const issues: string[] = [];

  const result = parseVorbisCodecPrivate(dv, 0, bytes.length, issues);

  assert.equal(result.vendor, null);
  assert.equal(result.truncated, true);
  assert.equal(result.headerPacketLengths, null);
  assert.ok(issues.length > 0);
});
