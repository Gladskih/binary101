"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";

import { createFileRangeReader } from "../../analyzers/file-range-reader.js";
import {
  finalizeInterfaces,
  parseInterfaceDescriptionBlock,
  parseInterfaceStatisticsBlock,
  parseNameResolutionBlock,
  parseSectionHeaderBlock
} from "../../analyzers/pcapng/metadata.js";
import type { SectionState } from "../../analyzers/pcapng/shared.js";
import {
  makeInterfaceDescription,
  makeInterfaceStatisticsBlock,
  makeSectionHeader
} from "../fixtures/pcapng-builder.js";
import { MockFile } from "../helpers/mock-file.js";

const NRB_TYPE = 0x00000004;

const makeSection = (): SectionState => ({ index: 0, littleEndian: true, interfaces: [] });

const makeReader = (bytes: Uint8Array, name: string): ReturnType<typeof createFileRangeReader> =>
  createFileRangeReader(new MockFile(bytes, name), 0, bytes.length);

const makeBlock = (type: number, body: Uint8Array): Uint8Array => {
  const bytes = new Uint8Array(12 + body.length);
  const view = new DataView(bytes.buffer);
  view.setUint32(0, type, true);
  view.setUint32(4, bytes.length, true);
  bytes.set(body, 8);
  view.setUint32(bytes.length - 4, bytes.length, true);
  return bytes;
};

void test("parseSectionHeaderBlock reports unusual versions and invalid negative section lengths", async () => {
  const block = makeSectionHeader({ littleEndian: true, versionMinor: 1 });
  const view = new DataView(block.buffer, block.byteOffset, block.byteLength);
  view.setBigInt64(16, -2n, true);
  const issues: string[] = [];

  const parsed = await parseSectionHeaderBlock(
    makeReader(block, "section.pcapng"),
    0,
    block.length,
    0,
    true,
    issue => issues.push(issue)
  );

  assert.strictEqual(parsed.summary.versionMinor, 1);
  assert.ok(issues.some(issue => issue.includes("uses pcapng version 1.1")));
  assert.ok(issues.some(issue => issue.includes("invalid Section Length -2")));
});

void test("parseInterfaceDescriptionBlock returns null for truncated blocks", async () => {
  const block = makeInterfaceDescription({ littleEndian: true, linkType: 1, snaplen: 64 });
  const issues: string[] = [];

  const parsed = await parseInterfaceDescriptionBlock(
    makeReader(block.subarray(0, 12), "truncated-idb.pcapng"),
    0,
    12,
    makeSection(),
    issue => issues.push(issue)
  );

  assert.strictEqual(parsed, null);
  assert.ok(issues.some(issue => issue.includes("is truncated")));
});

void test("parseNameResolutionBlock counts other records and missing end markers", async () => {
  const body = Uint8Array.from([
    0x03,
    0x00,
    0x04,
    0x00,
    0xde,
    0xad,
    0xbe,
    0xef
  ]);
  const issues: string[] = [];
  const summary = { ipv4Records: 0, ipv6Records: 0, otherRecords: 0, missingEndMarkers: 0 };

  await parseNameResolutionBlock(
    makeReader(makeBlock(NRB_TYPE, body), "other-nrb.pcapng"),
    0,
    20,
    makeSection(),
    summary,
    issue => issues.push(issue)
  );

  assert.strictEqual(summary.otherRecords, 1);
  assert.strictEqual(summary.missingEndMarkers, 1);
  assert.ok(issues.some(issue => issue.includes("missing nrb_record_end")));
});

void test("parseNameResolutionBlock reports records that run past the block", async () => {
  const body = Uint8Array.from([
    0x01,
    0x00,
    0x08,
    0x00,
    192,
    0,
    2,
    1
  ]);
  const issues: string[] = [];
  const summary = { ipv4Records: 0, ipv6Records: 0, otherRecords: 0, missingEndMarkers: 0 };

  await parseNameResolutionBlock(
    makeReader(makeBlock(NRB_TYPE, body), "overflow-nrb.pcapng"),
    0,
    20,
    makeSection(),
    summary,
    issue => issues.push(issue)
  );

  assert.strictEqual(summary.ipv4Records, 0);
  assert.ok(issues.some(issue => issue.includes("runs past the block")));
});

void test("parseInterfaceStatisticsBlock reports truncated and missing-interface blocks", async () => {
  const issues: string[] = [];
  await parseInterfaceStatisticsBlock(
    makeReader(new Uint8Array(16), "truncated-isb.pcapng"),
    0,
    16,
    makeSection(),
    issue => issues.push(issue)
  );

  const missingInterfaceBlock = makeInterfaceStatisticsBlock({
    littleEndian: true,
    interfaceId: 5,
    timestamp: 1_700_000_000_000_000n,
    captureStart: 1_700_000_000_000_000n,
    captureEnd: 1_700_000_001_000_000n,
    receivedPackets: 2n,
    droppedByInterface: 1n,
    deliveredToUser: 1n
  });
  await parseInterfaceStatisticsBlock(
    makeReader(missingInterfaceBlock, "missing-isb.pcapng"),
    0,
    missingInterfaceBlock.length,
    makeSection(),
    issue => issues.push(issue)
  );

  assert.ok(issues.some(issue => issue.includes("is truncated")));
  assert.ok(issues.some(issue => issue.includes("references missing interface 5")));
});

void test("parseInterfaceDescriptionBlock preserves large if_tsoffset values as bigint", async () => {
  const block = makeInterfaceDescription({
    littleEndian: true,
    linkType: 1,
    snaplen: 64,
    name: "eth0",
    tsoffsetSeconds: 9_007_199_254_740_992n
  });

  const parsed = await parseInterfaceDescriptionBlock(
    makeReader(block, "large-tsoffset-idb.pcapng"),
    0,
    block.length,
    makeSection(),
    () => undefined
  );

  assert.strictEqual(parsed?.timestampOffsetSeconds, 9_007_199_254_740_992n);
});

void test("finalizeInterfaces preserves null timestamp offsets after invalid metadata", async () => {
  const section = makeSection();
  const validBlock = makeInterfaceDescription({
    littleEndian: true,
    linkType: 1,
    snaplen: 64,
    name: "eth0"
  });
  const valid = await parseInterfaceDescriptionBlock(
    makeReader(validBlock, "valid-idb.pcapng"),
    0,
    validBlock.length,
    section,
    () => undefined
  );
  assert.ok(valid);

  const invalidTsoffset = Uint8Array.from(
    makeInterfaceDescription({ littleEndian: true, linkType: 1, snaplen: 64, name: "x" })
  );
  const invalidView = new DataView(invalidTsoffset.buffer, invalidTsoffset.byteOffset, invalidTsoffset.byteLength);
  invalidView.setUint16(16, 14, true);
  invalidView.setUint16(18, 4, true);
  const issues: string[] = [];
  const invalid = await parseInterfaceDescriptionBlock(
    makeReader(invalidTsoffset, "invalid-tsoffset-idb.pcapng"),
    0,
    invalidTsoffset.length,
    { ...section, interfaces: [valid] },
    issue => issues.push(issue)
  );
  assert.ok(invalid);

  const finalized = finalizeInterfaces([valid, invalid]);
  assert.strictEqual(finalized[1]?.timestampOffsetSeconds, null);
  assert.ok(issues.some(issue => issue.includes("unsupported if_tsoffset")));
});
