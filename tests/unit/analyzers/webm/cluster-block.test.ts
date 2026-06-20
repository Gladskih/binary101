"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";

import {
  emitStreamBlockTiming,
  parseStreamBlockHeader
} from "../../../../analyzers/webm/cluster-block.js";
import {
  createBlockWithTruncatedFlags,
  createBlockWithTruncatedTimecode,
  createFixedLacedBlock,
  createKeyframeBlockPayload,
  createLacedBlockWithoutCount
} from "../../../fixtures/webm-stream-fixtures.js";

// Distinct non-zero timestamps verify that Cluster and Block timecodes are added.
const TEST_TRACK_NUMBER = 1;
const RELATIVE_TIMECODE = 2;
const CLUSTER_TIMECODE = 10;

void test("parseStreamBlockHeader exposes timing and the bounded payload prefix", () => {
  // Ten ASCII bytes model the VP8 uncompressed keyframe header retained by the scanner.
  const payload = new TextEncoder().encode("vp8-header");
  const data = createKeyframeBlockPayload(TEST_TRACK_NUMBER, RELATIVE_TIMECODE, payload);
  const issues: string[] = [];
  const timing: Array<{ timecode: number | null; payload: Uint8Array | null }> = [];

  const block = parseStreamBlockHeader(data, issues);
  emitStreamBlockTiming(block, data, CLUSTER_TIMECODE, null, true, value => timing.push(value));

  assert.strictEqual(block.trackNumber, TEST_TRACK_NUMBER);
  assert.strictEqual(block.relativeTimecode, RELATIVE_TIMECODE);
  assert.strictEqual(timing[0]?.timecode, CLUSTER_TIMECODE + RELATIVE_TIMECODE);
  assert.deepEqual(timing[0]?.payload, payload);
  assert.deepEqual(issues, []);
});

void test("parseStreamBlockHeader reports a truncated lacing header", () => {
  const issues: string[] = [];

  const block = parseStreamBlockHeader(
    createLacedBlockWithoutCount(TEST_TRACK_NUMBER, 0),
    issues
  );

  assert.notStrictEqual(block.lacingMode, 0);
  assert.strictEqual(block.payloadOffset, null);
  assert.ok(issues.some(issue => issue.includes("lacing header is truncated")));
});

void test("parseStreamBlockHeader reads a fixed-lacing frame count", () => {
  const fixture = createFixedLacedBlock(TEST_TRACK_NUMBER, 0);

  const block = parseStreamBlockHeader(fixture.payload, []);

  assert.strictEqual(block.frames, fixture.frameCount);
  assert.strictEqual(block.payloadOffset, null);
});

void test("parseStreamBlockHeader tolerates missing timecode and flags", () => {
  const timecodeIssues: string[] = [];
  const flagIssues: string[] = [];

  const missingTimecode = parseStreamBlockHeader(createBlockWithTruncatedTimecode(), timecodeIssues);
  const missingFlags = parseStreamBlockHeader(createBlockWithTruncatedFlags(), flagIssues);

  assert.strictEqual(missingTimecode.relativeTimecode, null);
  assert.strictEqual(missingFlags.flags, null);
  assert.ok(timecodeIssues.some(issue => issue.includes("timecode is truncated")));
  assert.ok(flagIssues.some(issue => issue.includes("flags are truncated")));
});

void test("emitStreamBlockTiming ignores a block without timing", () => {
  const timing: unknown[] = [];

  const block = parseStreamBlockHeader(new Uint8Array(0), []);
  emitStreamBlockTiming(block, new Uint8Array(0), null, null, false, value => timing.push(value));

  assert.deepEqual(timing, []);
});
