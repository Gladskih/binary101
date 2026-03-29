"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";

import { createFileRangeReader } from "../../analyzers/file-range-reader.js";
import {
  parseEnhancedPacketBlock,
  parseLegacyPacketBlock,
  parseSimplePacketBlock
} from "../../analyzers/pcapng/packets.js";
import type { InterfaceState, SectionState } from "../../analyzers/pcapng/shared.js";
import { createMutableTrafficStats } from "../../analyzers/capture/stats.js";
import {
  makeEnhancedPacketBlock,
  makeEthernetFrame,
  makeIpv4Header,
  makePacketBlock,
  makeSimplePacketBlock
} from "../fixtures/pcapng-builder.js";
import { MockFile } from "../helpers/mock-file.js";

const makeInterface = (snaplen: number): InterfaceState => ({
  sectionIndex: 0,
  interfaceId: 0,
  linkType: 1,
  linkTypeName: "Ethernet",
  snaplen,
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

const makeSection = (interfaces: InterfaceState[]): SectionState => ({
  index: 0,
  littleEndian: true,
  interfaces
});

const makeReader = (bytes: Uint8Array, name: string): ReturnType<typeof createFileRangeReader> =>
  createFileRangeReader(new MockFile(bytes, name), 0, bytes.length);

const ipv4Frame = makeEthernetFrame(0x0800, makeIpv4Header(6));

void test("parseEnhancedPacketBlock reports truncated headers", async () => {
  const issues: string[] = [];

  await parseEnhancedPacketBlock(
    makeReader(new Uint8Array(20), "truncated-epb.pcapng"),
    0,
    20,
    makeSection([makeInterface(64)]),
    createMutableTrafficStats(),
    null,
    issue => issues.push(issue)
  );

  assert.ok(issues.some(issue => issue.includes("is truncated")));
});

void test("parseSimplePacketBlock warns when interface 0 is missing", async () => {
  const block = makeSimplePacketBlock({ littleEndian: true, payload: ipv4Frame, originalLength: ipv4Frame.length });
  const issues: string[] = [];
  const traffic = createMutableTrafficStats();

  await parseSimplePacketBlock(
    makeReader(block, "no-interface-spb.pcapng"),
    0,
    block.length,
    makeSection([]),
    traffic,
    null,
    issue => issues.push(issue)
  );

  assert.strictEqual(traffic.totalPackets, 1);
  assert.ok(issues.some(issue => issue.includes("requires interface 0")));
});

void test("parseSimplePacketBlock reports missing packet bytes when snaplen exceeds the stored payload", async () => {
  const block = makeSimplePacketBlock({
    littleEndian: true,
    payload: new Uint8Array(14),
    originalLength: 20
  });
  const issues: string[] = [];

  await parseSimplePacketBlock(
    makeReader(block, "short-spb.pcapng"),
    0,
    block.length,
    makeSection([makeInterface(64)]),
    createMutableTrafficStats(),
    null,
    issue => issues.push(issue)
  );

  assert.ok(issues.some(issue => issue.includes("does not contain the expected packet bytes")));
});

void test("parseLegacyPacketBlock reports truncated headers", async () => {
  const issues: string[] = [];

  await parseLegacyPacketBlock(
    makeReader(new Uint8Array(24), "truncated-pb.pcapng"),
    0,
    24,
    makeSection([makeInterface(64)]),
    createMutableTrafficStats(),
    null,
    issue => issues.push(issue)
  );

  assert.ok(issues.some(issue => issue.includes("Packet Block at 0x0 is truncated")));
});

void test("parseLegacyPacketBlock reports missing interfaces and option overlap safely", async () => {
  const block = makePacketBlock({
    littleEndian: true,
    interfaceId: 5,
    dropsCount: 1,
    timestamp: 1_700_000_000_000_000n,
    payload: ipv4Frame,
    originalLength: ipv4Frame.length
  });
  const view = new DataView(block.buffer, block.byteOffset, block.byteLength);
  view.setUint32(20, 128, true);
  const issues: string[] = [];

  await parseLegacyPacketBlock(
    makeReader(block, "missing-interface-pb.pcapng"),
    0,
    block.length,
    makeSection([makeInterface(64)]),
    createMutableTrafficStats(),
    null,
    issue => issues.push(issue)
  );

  assert.ok(issues.some(issue => issue.includes("references missing interface 5")));
  assert.ok(issues.some(issue => issue.includes("overlaps the block trailer")));
});

void test("parseEnhancedPacketBlock reports option overlap when captured length exceeds the block", async () => {
  const block = makeEnhancedPacketBlock({
    littleEndian: true,
    interfaceId: 0,
    timestamp: 1_700_000_000_000_000n,
    payload: ipv4Frame,
    originalLength: ipv4Frame.length
  });
  const view = new DataView(block.buffer, block.byteOffset, block.byteLength);
  view.setUint32(20, 256, true);
  const issues: string[] = [];

  await parseEnhancedPacketBlock(
    makeReader(block, "overlap-epb.pcapng"),
    0,
    block.length,
    makeSection([makeInterface(64)]),
    createMutableTrafficStats(),
    null,
    issue => issues.push(issue)
  );

  assert.ok(issues.some(issue => issue.includes("exceeds interface snaplen")));
  assert.ok(issues.some(issue => issue.includes("overlaps the block trailer")));
});
