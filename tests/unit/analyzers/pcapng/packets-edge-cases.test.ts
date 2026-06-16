"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";

import { createFileRangeReader } from "../../../../analyzers/file-range-reader.js";
import { createEthernetSummary } from "../../../../analyzers/capture/payload-analysis.js";
import { LINKTYPE_ETHERNET } from "../../../../analyzers/capture/link-types.js";
import { parseEnhancedPacketBlock } from "../../../../analyzers/pcapng/packets.js";
import type { InterfaceState, SectionState } from "../../../../analyzers/pcapng/shared.js";
import { createMutableTrafficStats } from "../../../../analyzers/capture/stats.js";
import {
  makeEnhancedPacketBlock,
  makeEthernetFrame,
  makeIpv4Header
} from "../../../fixtures/pcapng-builder.js";
import { MockFile } from "../../../helpers/mock-file.js";

const makeInterface = (
  snaplen: number,
  linkType = LINKTYPE_ETHERNET,
  linkTypeName = "Ethernet"
): InterfaceState => ({
  sectionIndex: 0,
  interfaceId: 0,
  linkType,
  linkTypeName,
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

void test("parseEnhancedPacketBlock accepts the exact fixed header size", async () => {
  // EPB fixed fields occupy 28 octets including the pcapng block type and total length.
  // Source: draft-ietf-opsawg-pcapng-05 Section 4.3.
  const enhancedPacketHeaderBytes = 28;
  const issues: string[] = [];

  await parseEnhancedPacketBlock(
    makeReader(new Uint8Array(enhancedPacketHeaderBytes), "exact-enhanced-header-epb.pcapng"),
    0,
    enhancedPacketHeaderBytes,
    makeSection([makeInterface(64)]),
    createMutableTrafficStats(),
    null,
    issue => issues.push(issue)
  );

  assert.ok(!issues.some(issue => issue.includes("is truncated")));
  assert.ok(
    issues.includes("Enhanced Packet Block at 0x0 has packet data that overlaps the block trailer.")
  );
});

void test("parseEnhancedPacketBlock reports captured lengths larger than original lengths", async () => {
  const block = makeEnhancedPacketBlock({
    littleEndian: true,
    interfaceId: 0,
    timestamp: 1_700_000_000_000_000n,
    payload: ipv4Frame,
    originalLength: ipv4Frame.length - 1
  });
  const issues: string[] = [];
  const traffic = createMutableTrafficStats();

  await parseEnhancedPacketBlock(
    makeReader(block, "captured-larger-than-original-epb.pcapng"),
    0,
    block.length,
    makeSection([makeInterface(64)]),
    traffic,
    null,
    issue => issues.push(issue)
  );

  assert.deepStrictEqual(issues, [
    `Packet #1 has captured length (${ipv4Frame.length}) larger than original ` +
      `length (${ipv4Frame.length - 1}).`
  ]);
  assert.strictEqual(traffic.totalCapturedBytes, ipv4Frame.length);
  assert.strictEqual(traffic.totalOriginalBytes, ipv4Frame.length - 1);
});

void test("parseEnhancedPacketBlock reports captured lengths beyond interface snaplen", async () => {
  const block = makeEnhancedPacketBlock({
    littleEndian: true,
    interfaceId: 0,
    timestamp: 1_700_000_000_000_000n,
    payload: ipv4Frame,
    originalLength: ipv4Frame.length
  });
  const issues: string[] = [];

  await parseEnhancedPacketBlock(
    makeReader(block, "captured-beyond-snaplen-epb.pcapng"),
    0,
    block.length,
    makeSection([makeInterface(ipv4Frame.length - 1)]),
    createMutableTrafficStats(),
    null,
    issue => issues.push(issue)
  );

  assert.deepStrictEqual(issues, [
    `Packet #1 captured length (${ipv4Frame.length}) exceeds interface ` +
      `snaplen (${ipv4Frame.length - 1}).`
  ]);
});

void test("parseEnhancedPacketBlock treats zero interface snaplen as unlimited", async () => {
  const block = makeEnhancedPacketBlock({
    littleEndian: true,
    interfaceId: 0,
    timestamp: 1_700_000_000_000_000n,
    payload: ipv4Frame,
    originalLength: ipv4Frame.length
  });
  const issues: string[] = [];
  const traffic = createMutableTrafficStats();

  await parseEnhancedPacketBlock(
    makeReader(block, "zero-snaplen-epb.pcapng"),
    0,
    block.length,
    makeSection([makeInterface(0)]),
    traffic,
    null,
    issue => issues.push(issue)
  );

  assert.deepStrictEqual(issues, []);
  assert.strictEqual(traffic.totalCapturedBytes, ipv4Frame.length);
  assert.strictEqual(traffic.truncatedPackets, 0);
});

void test("parseEnhancedPacketBlock skips Ethernet analysis for non-Ethernet interfaces", async () => {
  const block = makeEnhancedPacketBlock({
    littleEndian: true,
    interfaceId: 0,
    timestamp: 1_700_000_000_000_000n,
    payload: ipv4Frame,
    originalLength: ipv4Frame.length
  });
  const linkLayer = { ethernet: createEthernetSummary() };

  await parseEnhancedPacketBlock(
    makeReader(block, "non-ethernet-epb.pcapng"),
    0,
    block.length,
    // PCAP LinkType registry: 0 is LINKTYPE_NULL, a non-Ethernet loopback type.
    makeSection([makeInterface(64, 0, "Null/loopback")]),
    createMutableTrafficStats(),
    linkLayer,
    () => undefined
  );

  assert.strictEqual(linkLayer.ethernet.framesParsed, 0);
  assert.strictEqual(linkLayer.ethernet.shortFrames, 0);
});

void test("parseEnhancedPacketBlock reports malformed drop-count options with context", async () => {
  const block = makeEnhancedPacketBlock({
    littleEndian: true,
    interfaceId: 0,
    timestamp: 1_700_000_000_000_000n,
    payload: ipv4Frame,
    originalLength: ipv4Frame.length,
    dropCount: 1n
  });
  const view = new DataView(block.buffer, block.byteOffset, block.byteLength);
  // EPB fixed fields occupy 28 octets; packet data is padded to the pcapng 32-bit boundary.
  // Source: draft-ietf-opsawg-pcapng-05 Section 4.3.
  const dropCountOptionOffset = 28 + Math.ceil(ipv4Frame.length / 4) * 4;
  view.setUint16(dropCountOptionOffset + 2, 4, true);
  view.setUint32(dropCountOptionOffset + 8, 0, true);
  const issues: string[] = [];

  await parseEnhancedPacketBlock(
    makeReader(block, "short-dropcount-epb.pcapng"),
    0,
    block.length,
    makeSection([makeInterface(64)]),
    createMutableTrafficStats(),
    null,
    issue => issues.push(issue)
  );

  assert.deepStrictEqual(issues, [
    "Enhanced Packet Block at 0x0 option 4 does not contain an 8-byte integer."
  ]);
});

void test("parseEnhancedPacketBlock reports invalid timestamp metadata with context", async () => {
  const block = makeEnhancedPacketBlock({
    littleEndian: true,
    interfaceId: 0,
    timestamp: 1_700_000_000_000_000n,
    payload: ipv4Frame,
    originalLength: ipv4Frame.length
  });
  const interfaceState = makeInterface(64);
  interfaceState.timestampOffsetSeconds = null;
  const issues: string[] = [];

  await parseEnhancedPacketBlock(
    makeReader(block, "invalid-timestamp-epb.pcapng"),
    0,
    block.length,
    makeSection([interfaceState]),
    createMutableTrafficStats(),
    null,
    issue => issues.push(issue)
  );

  assert.deepStrictEqual(issues, [
    "Enhanced Packet Block at 0x0 depends on an invalid if_tsoffset value and cannot be represented exactly."
  ]);
});
