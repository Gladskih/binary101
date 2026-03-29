"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";

import { createFileRangeReader } from "../../analyzers/file-range-reader.js";
import {
  getTimestampSeconds,
  readMetadataBlock,
  readUint64OptionValue
} from "../../analyzers/pcapng/shared.js";
import { createMutableTrafficStats } from "../../analyzers/capture/stats.js";
import type { InterfaceState } from "../../analyzers/pcapng/shared.js";
import { MockFile } from "../helpers/mock-file.js";

const makeInterface = (): InterfaceState => ({
  sectionIndex: 0,
  interfaceId: 0,
  linkType: 1,
  linkTypeName: "Ethernet",
  snaplen: 64,
  name: "eth0",
  description: null,
  hardware: null,
  os: null,
  filter: null,
  timestampResolution: "10^-6 s",
  unitsPerSecond: 1_000_000,
  timestampOffsetSeconds: 0n,
  observedDropCount: null,
  statistics: null,
  traffic: createMutableTrafficStats()
});

void test("readMetadataBlock reads oversized blocks in full", async () => {
  const bytes = new Uint8Array(128 * 1024 + 16);
  const reader = createFileRangeReader(new MockFile(bytes, "large-block.pcapng"), 0, bytes.length);

  const block = await readMetadataBlock(reader, 0, bytes.length);

  assert.strictEqual(block.byteLength, bytes.length);
});

void test("getTimestampSeconds reports non-finite timestamps", () => {
  const issues: string[] = [];
  const interfaceState = makeInterface();
  interfaceState.unitsPerSecond = 0;

  const seconds = getTimestampSeconds(
    interfaceState,
    0xffffffff,
    0xffffffff,
    issue => issues.push(issue),
    "timestamp"
  );

  assert.strictEqual(seconds, null);
  assert.ok(issues.some(issue => issue.includes("cannot be represented precisely")));
});

void test("getTimestampSeconds reports invalid bigint timestamp offsets", () => {
  const issues: string[] = [];
  const interfaceState = makeInterface();
  interfaceState.timestampOffsetSeconds = null;

  const seconds = getTimestampSeconds(interfaceState, 0, 1, issue => issues.push(issue), "timestamp");

  assert.strictEqual(seconds, null);
  assert.ok(issues.some(issue => issue.includes("invalid if_tsoffset")));
});

void test("readUint64OptionValue reports malformed integer options", () => {
  const issues: string[] = [];

  const value = readUint64OptionValue(
    [{ code: 4, value: Uint8Array.from([1, 2, 3, 4]) }],
    4,
    true,
    issue => issues.push(issue),
    "option-test"
  );

  assert.strictEqual(value, null);
  assert.ok(issues.some(issue => issue.includes("does not contain an 8-byte integer")));
});
