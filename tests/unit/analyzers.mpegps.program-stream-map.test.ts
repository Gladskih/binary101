"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";

import { parseProgramStreamMap } from "../../analyzers/mpegps/program-stream-map.js";

const createIssueCollector = (): { issues: string[]; pushIssue: (message: string) => void } => {
  const issues: string[] = [];
  return { issues, pushIssue: message => issues.push(String(message)) };
};

void test("parseProgramStreamMap reports too-small payloads", () => {
  const { issues, pushIssue } = createIssueCollector();
  const parsed = parseProgramStreamMap(new Uint8Array(9), pushIssue);
  assert.strictEqual(issues.length, 1);
  assert.strictEqual(issues[0], "Program Stream Map is too small to parse.");
  assert.strictEqual(parsed.currentNextIndicator, null);
  assert.strictEqual(parsed.version, null);
  assert.strictEqual(parsed.entries.length, 0);
  assert.strictEqual(parsed.crc32, null);
});

void test("parseProgramStreamMap warns when marker bit is missing", () => {
  const { issues, pushIssue } = createIssueCollector();
  const payload = new Uint8Array([
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xde, 0xad, 0xbe, 0xef
  ]);
  const parsed = parseProgramStreamMap(payload, pushIssue);
  assert.strictEqual(issues.length, 1);
  assert.strictEqual(issues[0], "Program Stream Map marker bit is not set.");
  assert.strictEqual(parsed.currentNextIndicator, false);
  assert.strictEqual(parsed.version, 0);
  assert.strictEqual(parsed.entries.length, 0);
  assert.strictEqual(parsed.crc32, 0xdeadbeef);
});

void test("parseProgramStreamMap reports truncation inside program_stream_info", () => {
  const { issues, pushIssue } = createIssueCollector();
  const payload = new Uint8Array([
    0x81, 0x01, 0x00, 0x05, 0x11, 0x22, 0x33, 0x44, 0x55, 0x00
  ]);
  const parsed = parseProgramStreamMap(payload, pushIssue);
  assert.strictEqual(issues.length, 1);
  assert.strictEqual(issues[0], "Program Stream Map ended while skipping program_stream_info.");
  assert.strictEqual(parsed.programStreamInfoLength, 5);
  assert.strictEqual(parsed.elementaryStreamMapLength, null);
  assert.strictEqual(parsed.entries.length, 0);
  assert.strictEqual(parsed.crc32, null);
});

void test("parseProgramStreamMap warns when stream map length exceeds payload", () => {
  const { issues, pushIssue } = createIssueCollector();
  const payload = new Uint8Array([
    0x80, 0x01, 0x00, 0x00, 0x00, 0x10, 0x1b, 0xe0, 0x00, 0x00, 0x04, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00
  ]);
  const parsed = parseProgramStreamMap(payload, pushIssue);
  assert.ok(issues.includes("Program Stream Map elementary stream map length exceeds payload."));
  assert.strictEqual(parsed.entries.length, 2);
  assert.strictEqual(parsed.crc32, 0);
});

void test("parseProgramStreamMap parses entries and CRC32", () => {
  const { issues, pushIssue } = createIssueCollector();
  const payload = new Uint8Array([
    0x81, 0x01, 0x00, 0x00, 0x00, 0x06, 0x1b, 0xe0, 0x00, 0x02, 0xaa, 0xbb, 0x12, 0x34, 0x56, 0x78
  ]);
  const parsed = parseProgramStreamMap(payload, pushIssue);
  assert.strictEqual(issues.length, 0);
  assert.strictEqual(parsed.currentNextIndicator, true);
  assert.strictEqual(parsed.version, 1);
  assert.strictEqual(parsed.programStreamInfoLength, 0);
  assert.strictEqual(parsed.elementaryStreamMapLength, 6);
  assert.strictEqual(parsed.entries.length, 1);
  const entry = parsed.entries[0];
  assert.ok(entry);
  assert.strictEqual(entry.streamType, 0x1b);
  assert.strictEqual(entry.elementaryStreamId, 0xe0);
  assert.strictEqual(entry.elementaryStreamInfoLength, 2);
  assert.strictEqual(parsed.crc32, 0x12345678);
});
