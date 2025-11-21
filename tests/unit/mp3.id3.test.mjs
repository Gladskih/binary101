"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { parseId3v1, parseId3v2 } from "../../analyzers/mp3/id3.js";

const asciiBytes = text => Array.from(Buffer.from(text, "latin1"));

const encodeSyncsafe = value => [
  (value >> 21) & 0x7f,
  (value >> 14) & 0x7f,
  (value >> 7) & 0x7f,
  value & 0x7f
];

const buildFrame = (id, payload) => {
  const frame = new Uint8Array(10 + payload.length);
  frame.set(asciiBytes(id), 0);
  const dv = new DataView(frame.buffer);
  dv.setUint32(4, payload.length, false);
  dv.setUint16(8, 0, false);
  frame.set(payload, 10);
  return frame;
};

const concat = arrays => {
  const total = arrays.reduce((sum, arr) => sum + arr.length, 0);
  const out = new Uint8Array(total);
  let cursor = 0;
  for (const arr of arrays) {
    out.set(arr, cursor);
    cursor += arr.length;
  }
  return out;
};

test("parseId3v2 parses multiple frame types", () => {
  const textFrame = buildFrame("TPE1", Uint8Array.from([0x00, ...asciiBytes("Artist")]));
  const txxxFrame = buildFrame(
    "TXXX",
    Uint8Array.from([0x00, ...asciiBytes("desc"), 0x00, ...asciiBytes("custom value")])
  );
  const wxxxFrame = buildFrame(
    "WXXX",
    Uint8Array.from([0x00, ...asciiBytes("home"), 0x00, ...asciiBytes("https://example.com")])
  );
  const commFrame = buildFrame("COMM", Uint8Array.from([0x00, ...asciiBytes("eng"), 0x00]));
  const apicFrame = buildFrame(
    "APIC",
    Uint8Array.from([
      0x00,
      ...asciiBytes("image/png"),
      0x00,
      0x03,
      ...asciiBytes("cover"),
      0x00,
      ...Uint8Array.from([1, 2, 3, 4])
    ])
  );
  const wAlternateFrame = buildFrame(
    "WCOM",
    Uint8Array.from(asciiBytes("https://tickets.example"))
  );

  const frames = concat([textFrame, txxxFrame, wxxxFrame, commFrame, apicFrame, wAlternateFrame]);
  const header = new Uint8Array(10);
  header.set(asciiBytes("ID3"), 0);
  header[3] = 3;
  header[4] = 0;
  header[5] = 0x80; // unsynchronisation flag set to trigger notice
  const size = frames.length;
  header.set(encodeSyncsafe(size), 6);

  const tag = concat([header, frames]);
  const resultIssues = [];
  const parsed = parseId3v2(new DataView(tag.buffer), resultIssues);

  assert.ok(parsed);
  assert.strictEqual(parsed.versionMajor, 3);
  assert.strictEqual(parsed.frames.length, 6);
  assert.ok(resultIssues.some(msg => msg.includes("unsynchronisation")));

  const apic = parsed.frames.find(f => f.id === "APIC");
  assert.strictEqual(apic?.detail.type, "apic");
  assert.strictEqual(apic.detail.mimeType, "image/png");

  const text = parsed.frames.find(f => f.id === "TPE1");
  assert.strictEqual(text?.detail.value, "Artist");

  const url = parsed.frames.find(f => f.id === "WCOM");
  assert.strictEqual(url?.detail.url, "https://tickets.example");
});

test("parseId3v2 handles extended headers and truncation warnings", () => {
  const header = new Uint8Array(10);
  header.set(asciiBytes("ID3"), 0);
  header[3] = 3;
  header[4] = 0;
  header[5] = 0x40; // extended header
  const tagSize = 20;
  header.set(encodeSyncsafe(tagSize), 6);

  const extHeader = new Uint8Array([0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
  const truncatedFrame = buildFrame("TPE1", Uint8Array.from([0x00, ...asciiBytes("A")]));
  const combined = concat([header, extHeader, truncatedFrame]);
  const issues = [];
  const parsed = parseId3v2(new DataView(combined.buffer), issues);

  assert.ok(parsed);
  assert.ok(issues.some(msg => msg.includes("truncated")));
});

test("parseId3v2 returns null or warnings for invalid tags", () => {
  // Missing header
  assert.strictEqual(parseId3v2(new DataView(new ArrayBuffer(4)), []), null);

  // Bad sync-safe size
  const badHeader = Uint8Array.from([
    ...asciiBytes("ID3"),
    3,
    0,
    0,
    0xff,
    0xff,
    0xff,
    0xff
  ]);
  const issues = [];
  const parsed = parseId3v2(new DataView(badHeader.buffer), issues);
  assert.ok(parsed);
  assert.ok(issues.some(msg => msg.includes("Invalid ID3v2 tag size")));
});

test("parseId3v1 extracts classic 128-byte footer", () => {
  const data = new Uint8Array(200).fill(0x20);
  const start = data.length - 128;
  data.set(asciiBytes("TAG"), start);
  data.set(asciiBytes("Title"), start + 3);
  data.set(asciiBytes("Artist"), start + 33);
  data.set(asciiBytes("Album"), start + 63);
  data.set(asciiBytes("1999"), start + 93);
  data[start + 125] = 0;
  data[start + 126] = 4; // track number
  data[start + 127] = 8; // genre code

  const parsed = parseId3v1(new DataView(data.buffer));

  assert.ok(parsed);
  assert.strictEqual(parsed.title, "Title");
  assert.strictEqual(parsed.artist, "Artist");
  assert.strictEqual(parsed.album, "Album");
  assert.strictEqual(parsed.year, "1999");
  assert.strictEqual(parsed.trackNumber, 4);
  assert.strictEqual(parsed.genreCode, 8);
});
