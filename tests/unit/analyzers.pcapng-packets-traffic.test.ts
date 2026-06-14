"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";

import { createFileRangeReader } from "../../analyzers/file-range-reader.js";
import { createEthernetSummary } from "../../analyzers/capture/payload-analysis.js";
import { LINKTYPE_ETHERNET } from "../../analyzers/capture/link-types.js";
import {
  parseLegacyPacketBlock,
  parseSimplePacketBlock
} from "../../analyzers/pcapng/packets.js";
import type { InterfaceState, SectionState } from "../../analyzers/pcapng/shared.js";
import { createMutableTrafficStats } from "../../analyzers/capture/stats.js";
import {
  makeEthernetFrame,
  makeIpv4Header,
  makePacketBlock,
  makeSimplePacketBlock
} from "../fixtures/pcapng-builder.js";
import { MockFile } from "../helpers/mock-file.js";

const makeInterface = (snaplen: number): InterfaceState => ({
  sectionIndex: 0,
  interfaceId: 0,
  linkType: LINKTYPE_ETHERNET,
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

void test("parseSimplePacketBlock caps captured length at interface snaplen", async () => {
  const block = makeSimplePacketBlock({
    littleEndian: true,
    payload: ipv4Frame,
    originalLength: ipv4Frame.length
  });
  const ethernetHeaderMinusOne = 13; // Ethernet II base header is 14 octets.
  const issues: string[] = [];
  const traffic = createMutableTrafficStats();
  const linkLayer = { ethernet: createEthernetSummary() };

  await parseSimplePacketBlock(
    makeReader(block, "snaplen-capped-spb.pcapng"),
    0,
    block.length,
    makeSection([makeInterface(ethernetHeaderMinusOne)]),
    traffic,
    linkLayer,
    issue => issues.push(issue)
  );

  assert.deepStrictEqual(issues, []);
  assert.strictEqual(traffic.totalCapturedBytes, ethernetHeaderMinusOne);
  assert.strictEqual(traffic.totalOriginalBytes, ipv4Frame.length);
  assert.strictEqual(traffic.truncatedPackets, 1);
  assert.strictEqual(linkLayer.ethernet.framesParsed, 0);
  assert.strictEqual(linkLayer.ethernet.shortFrames, 1);
});

void test("parseSimplePacketBlock treats zero interface snaplen as unlimited", async () => {
  const block = makeSimplePacketBlock({
    littleEndian: true,
    payload: ipv4Frame,
    originalLength: ipv4Frame.length
  });
  const issues: string[] = [];
  const traffic = createMutableTrafficStats();

  await parseSimplePacketBlock(
    makeReader(block, "zero-snaplen-spb.pcapng"),
    0,
    block.length,
    makeSection([makeInterface(0)]),
    traffic,
    null,
    issue => issues.push(issue)
  );

  assert.deepStrictEqual(issues, []);
  assert.strictEqual(traffic.totalCapturedBytes, ipv4Frame.length);
  assert.strictEqual(traffic.totalOriginalBytes, ipv4Frame.length);
  assert.strictEqual(traffic.truncatedPackets, 0);
});

void test("parseLegacyPacketBlock records captured and original byte counts", async () => {
  const block = makePacketBlock({
    littleEndian: true,
    interfaceId: 0,
    dropsCount: 0xffff,
    timestamp: 1_700_000_000_000_000n,
    payload: ipv4Frame,
    originalLength: ipv4Frame.length + 1
  });
  const issues: string[] = [];
  const traffic = createMutableTrafficStats();
  const interfaceState = makeInterface(64);

  await parseLegacyPacketBlock(
    makeReader(block, "packet-byte-counts-pb.pcapng"),
    0,
    block.length,
    makeSection([interfaceState]),
    traffic,
    null,
    issue => issues.push(issue)
  );

  assert.deepStrictEqual(issues, []);
  assert.strictEqual(traffic.totalCapturedBytes, ipv4Frame.length);
  assert.strictEqual(traffic.totalOriginalBytes, ipv4Frame.length + 1);
  assert.strictEqual(traffic.truncatedPackets, 1);
  assert.strictEqual(interfaceState.observedDropCount, null);
});

void test("parseLegacyPacketBlock reports invalid timestamp metadata with context", async () => {
  const block = makePacketBlock({
    littleEndian: true,
    interfaceId: 0,
    dropsCount: 0xffff,
    timestamp: 1_700_000_000_000_000n,
    payload: ipv4Frame,
    originalLength: ipv4Frame.length
  });
  const interfaceState = makeInterface(64);
  interfaceState.timestampOffsetSeconds = null;
  const issues: string[] = [];

  await parseLegacyPacketBlock(
    makeReader(block, "invalid-timestamp-pb.pcapng"),
    0,
    block.length,
    makeSection([interfaceState]),
    createMutableTrafficStats(),
    null,
    issue => issues.push(issue)
  );

  assert.deepStrictEqual(issues, [
    "Packet Block at 0x0 depends on an invalid if_tsoffset value and cannot be represented exactly."
  ]);
});
