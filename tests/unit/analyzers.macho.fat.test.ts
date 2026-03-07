"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { FAT_MAGIC, FAT_MAGIC_64 } from "../../analyzers/macho/commands.js";
import { getMachOMagicInfo } from "../../analyzers/macho/format.js";
import { parseFatBinary } from "../../analyzers/macho/fat.js";
import {
  CPU_SUBTYPE_X86_64_ALL,
  CPU_TYPE_X86_64,
  createThinMachOFixture
} from "../fixtures/macho-thin-sample.js";
import { createMachOUniversalLayout, wrapMachOBytes } from "../fixtures/macho-fixtures.js";
import { createSliceTrackingFile } from "../helpers/slice-tracking-file.js";

const fatMagicInfo = (bytes: Uint8Array) => {
  const magicInfo = getMachOMagicInfo(new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength));
  assert.ok(magicInfo);
  assert.equal(magicInfo.kind, "fat");
  return magicInfo;
};

void test("parseFatBinary reports truncated fat headers", async () => {
  const bytes = new Uint8Array(4);
  new DataView(bytes.buffer).setUint32(0, FAT_MAGIC, false);
  const parsed = await parseFatBinary(wrapMachOBytes(bytes, "fat-truncated"), fatMagicInfo(bytes));
  assert.equal(parsed.fatHeader, null);
  assert.match(parsed.issues[0] || "", /Fat header is truncated/);
});

void test("parseFatBinary reports missing architecture records", async () => {
  const bytes = new Uint8Array(8);
  const view = new DataView(bytes.buffer);
  view.setUint32(0, FAT_MAGIC, false);
  view.setUint32(4, 2, false);
  const parsed = await parseFatBinary(wrapMachOBytes(bytes, "fat-empty"), fatMagicInfo(bytes));
  assert.equal(parsed.slices.length, 0);
  assert.match(parsed.issues[0] || "", /declares 2 slices but only 0 architecture records fit/);
});

void test("parseFatBinary reports slices that extend past the file", async () => {
  const fixture = createMachOUniversalLayout();
  const bytes = fixture.bytes;
  const view = new DataView(bytes.buffer);
  view.setUint32(20, bytes.length, false);
  const parsed = await parseFatBinary(wrapMachOBytes(bytes, "fat-range"), fatMagicInfo(bytes));
  assert.match(parsed.slices[0]?.issues[0] || "", /extends beyond the file/);
});

void test("parseFatBinary reports slices without supported Mach-O payloads", async () => {
  const fixture = createMachOUniversalLayout();
  const bytes = fixture.bytes;
  const view = new DataView(bytes.buffer);
  view.setUint32(fixture.slice0Offset, 0, false);
  const parsed = await parseFatBinary(wrapMachOBytes(bytes, "fat-invalid-slice"), fatMagicInfo(bytes));
  assert.match(parsed.slices[0]?.issues[0] || "", /does not contain a supported Mach-O image/);
});

void test("parseFatBinary parses FAT_MAGIC_64 slice records", async () => {
  const thin = createThinMachOFixture(
    CPU_TYPE_X86_64,
    CPU_SUBTYPE_X86_64_ALL,
    0x44,
    "com.example.binary101.fat64"
  ).bytes;
  const sliceOffset = 0x1000;
  const bytes = new Uint8Array(sliceOffset + thin.length);
  const view = new DataView(bytes.buffer);
  view.setUint32(0, FAT_MAGIC_64, false);
  view.setUint32(4, 1, false);
  view.setUint32(8, CPU_TYPE_X86_64, false);
  view.setUint32(12, CPU_SUBTYPE_X86_64_ALL, false);
  view.setBigUint64(16, BigInt(sliceOffset), false);
  view.setBigUint64(24, BigInt(thin.length), false);
  view.setUint32(32, 12, false);
  view.setUint32(36, 0x1234, false);
  bytes.set(thin, sliceOffset);

  const parsed = await parseFatBinary(wrapMachOBytes(bytes, "fat64-valid"), fatMagicInfo(bytes));

  assert.equal(parsed.fatHeader?.is64, true);
  assert.equal(parsed.slices.length, 1);
  assert.equal(parsed.slices[0]?.offset, sliceOffset);
  assert.equal(parsed.slices[0]?.size, thin.length);
  assert.equal(parsed.slices[0]?.align, 12);
  assert.equal(parsed.slices[0]?.reserved, 0x1234);
  assert.equal(parsed.slices[0]?.image?.header.is64, true);
  assert.deepEqual(parsed.issues, []);
});

void test("parseFatBinary reads fat slice records incrementally", async () => {
  const bytes = new Uint8Array(0x10028);
  const view = new DataView(bytes.buffer);
  view.setUint32(0, FAT_MAGIC_64, false);
  view.setUint32(4, 0xffffffff, false);
  const tracked = createSliceTrackingFile(bytes, bytes.length, "fat-incremental");

  const parsed = await parseFatBinary(tracked.file, fatMagicInfo(bytes));

  assert.equal(parsed.slices.length, Math.floor((bytes.length - 8) / 32));
  assert.ok(Math.max(...tracked.requests) < tracked.file.size);
});
