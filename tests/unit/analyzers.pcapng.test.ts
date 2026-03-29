"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";

import { parsePcapNg, type PcapNgParseResult } from "../../analyzers/pcapng/index.js";
import {
  createPcapNgBigEndianFile,
  createPcapNgFile,
  createPcapNgMissingInterfaceFile,
  createTruncatedPcapNgFile
} from "../fixtures/pcapng-fixtures.js";
import {
  concatParts,
  makeCustomBlock,
  makeSectionHeader
} from "../fixtures/pcapng-builder.js";
import { MockFile } from "../helpers/mock-file.js";

const CUSTOM_BLOCK_NOCOPY_TYPE = 0x40000bad;
const UNKNOWN_BLOCK_TYPE = 0x12345678;

const expectPcapNg = (parsed: PcapNgParseResult | null): PcapNgParseResult => {
  assert.ok(parsed);
  assert.strictEqual(parsed.format, "pcapng");
  return parsed;
};

void test("parsePcapNg parses pcapng sections, interfaces, and block summaries", async () => {
  const parsed = expectPcapNg(await parsePcapNg(createPcapNgFile()));

  assert.strictEqual(parsed.sections.length, 1);
  assert.strictEqual(parsed.sections[0]?.littleEndian, true);
  assert.strictEqual(parsed.interfaces.length, 2);
  assert.strictEqual(parsed.blocks.totalBlocks, 11);
  assert.strictEqual(parsed.blocks.interfaceDescriptionBlocks, 2);
  assert.strictEqual(parsed.blocks.enhancedPacketBlocks, 2);
  assert.strictEqual(parsed.blocks.simplePacketBlocks, 1);
  assert.strictEqual(parsed.blocks.packetBlocks, 1);
  assert.strictEqual(parsed.blocks.nameResolutionBlocks, 1);
  assert.strictEqual(parsed.blocks.interfaceStatisticsBlocks, 1);
  assert.strictEqual(parsed.blocks.decryptionSecretsBlocks, 1);
  assert.strictEqual(parsed.blocks.customBlocks, 1);
  assert.strictEqual(parsed.packets.totalPackets, 4);
  assert.strictEqual(parsed.packets.truncatedPackets, 1);
  assert.strictEqual(parsed.packets.outOfOrderTimestamps, 1);
  assert.strictEqual(parsed.nameResolution.ipv4Records, 1);
  assert.strictEqual(parsed.nameResolution.ipv6Records, 1);

  const firstInterface = parsed.interfaces[0];
  assert.ok(firstInterface);
  assert.strictEqual(firstInterface.name, "eth0");
  assert.strictEqual(firstInterface.packets.totalPackets, 2);
  assert.strictEqual(firstInterface.observedDropCount, 3n);
  assert.strictEqual(firstInterface.statistics?.receivedPackets, 4n);

  const secondInterface = parsed.interfaces[1];
  assert.ok(secondInterface);
  assert.strictEqual(secondInterface.name, "wlan0");
  assert.strictEqual(secondInterface.timestampOffsetSeconds, 2n);
  assert.strictEqual(secondInterface.packets.totalPackets, 2);
  assert.strictEqual(secondInterface.observedDropCount, 7n);

  const eth = parsed.linkLayer?.ethernet;
  assert.ok(eth);
  assert.strictEqual(eth.framesParsed, 4);
  assert.strictEqual(eth.etherTypes.get(0x0800) || 0, 1);
  assert.strictEqual(eth.etherTypes.get(0x86dd) || 0, 1);
  assert.strictEqual(eth.etherTypes.get(0x0806) || 0, 2);
});

void test("parsePcapNg supports big-endian pcapng sections", async () => {
  const parsed = expectPcapNg(await parsePcapNg(createPcapNgBigEndianFile()));

  assert.strictEqual(parsed.sections.length, 1);
  assert.strictEqual(parsed.sections[0]?.littleEndian, false);
  assert.strictEqual(parsed.interfaces.length, 1);
  assert.strictEqual(parsed.packets.totalPackets, 1);
  assert.strictEqual(parsed.interfaces[0]?.packets.totalPackets, 1);
});

void test("parsePcapNg warns when a pcapng packet block references a missing interface", async () => {
  const parsed = expectPcapNg(await parsePcapNg(createPcapNgMissingInterfaceFile()));

  assert.strictEqual(parsed.packets.totalPackets, 1);
  assert.ok(parsed.issues.some(issue => issue.includes("missing interface 7")));
});

void test("parsePcapNg reports truncation for truncated pcapng files", async () => {
  const parsed = expectPcapNg(await parsePcapNg(createTruncatedPcapNgFile()));

  assert.strictEqual(parsed.packets.truncatedFile, true);
  assert.ok(parsed.issues.some(issue => issue.includes("trailing bytes")));
});

void test("parsePcapNg treats a section header with an invalid byte-order magic as malformed pcapng", async () => {
  const bytes = Uint8Array.from(makeSectionHeader({ littleEndian: true }));
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  view.setUint32(8, 0, true);

  const parsed = expectPcapNg(await parsePcapNg(new MockFile(bytes, "bad-magic.pcapng")));

  assert.strictEqual(parsed.packets.truncatedFile, true);
  assert.ok(parsed.issues.some(issue => issue.includes("before a valid Section Header Block")));
});

void test("parsePcapNg reports truncated block headers after a valid section", async () => {
  const file = new MockFile(
    concatParts([makeSectionHeader({ littleEndian: true }), new Uint8Array(8)]),
    "truncated-header.pcapng"
  );
  const parsed = expectPcapNg(await parsePcapNg(file));

  assert.strictEqual(parsed.packets.truncatedFile, true);
  assert.ok(parsed.issues.some(issue => issue.includes("Block header at 0x20 is truncated")));
});

void test("parsePcapNg reports invalid block lengths", async () => {
  const brokenBlock = new Uint8Array(12);
  const view = new DataView(brokenBlock.buffer);
  view.setUint32(0, 1, true);
  view.setUint32(4, 14, true);
  const file = new MockFile(
    concatParts([makeSectionHeader({ littleEndian: true }), brokenBlock]),
    "invalid-length.pcapng"
  );
  const parsed = expectPcapNg(await parsePcapNg(file));

  assert.strictEqual(parsed.packets.truncatedFile, true);
  assert.ok(parsed.issues.some(issue => issue.includes("invalid Block Total Length 14")));
});

void test("parsePcapNg counts no-copy custom blocks, unknown blocks, and mismatched trailers", async () => {
  const noCopyCustom = Uint8Array.from(makeCustomBlock(true));
  const noCopyView = new DataView(noCopyCustom.buffer, noCopyCustom.byteOffset, noCopyCustom.byteLength);
  noCopyView.setUint32(0, CUSTOM_BLOCK_NOCOPY_TYPE, true);

  const unknownBlock = Uint8Array.from(makeCustomBlock(true));
  const unknownView = new DataView(unknownBlock.buffer, unknownBlock.byteOffset, unknownBlock.byteLength);
  unknownView.setUint32(0, UNKNOWN_BLOCK_TYPE, true);
  unknownView.setUint32(unknownBlock.length - 4, unknownBlock.length - 4, true);

  const file = new MockFile(
    concatParts([makeSectionHeader({ littleEndian: true }), noCopyCustom, unknownBlock]),
    "custom-and-unknown.pcapng"
  );
  const parsed = expectPcapNg(await parsePcapNg(file));

  assert.strictEqual(parsed.blocks.customBlocks, 1);
  assert.strictEqual(parsed.blocks.unknownBlocks, 1);
  assert.ok(parsed.issues.some(issue => issue.includes("mismatched trailing Block Total Length")));
});
