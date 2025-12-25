"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";

import { parsePcap } from "../../analyzers/pcap/index.js";
import { createPcapBigEndianFile, createPcapFile } from "../fixtures/pcap-fixtures.js";
import { MockFile } from "../helpers/mock-file.js";

const concatParts = (parts: Uint8Array[]): Uint8Array => {
  const total = parts.reduce((sum, part) => sum + part.length, 0);
  const out = new Uint8Array(total);
  let cursor = 0;
  for (const part of parts) {
    out.set(part, cursor);
    cursor += part.length;
  }
  return out;
};

const makeGlobalHeader = (opts: {
  littleEndian: boolean;
  nanoseconds?: boolean;
  versionMajor?: number;
  versionMinor?: number;
  network: number;
  snaplen: number;
}): Uint8Array => {
  const header = new Uint8Array(24);
  const dv = new DataView(header.buffer);
  const magic = opts.nanoseconds ? 0xa1b23c4d : 0xa1b2c3d4;
  dv.setUint32(0, magic, opts.littleEndian);
  dv.setUint16(4, opts.versionMajor ?? 2, opts.littleEndian);
  dv.setUint16(6, opts.versionMinor ?? 4, opts.littleEndian);
  dv.setInt32(8, 0, opts.littleEndian);
  dv.setUint32(12, 0, opts.littleEndian);
  dv.setUint32(16, opts.snaplen >>> 0, opts.littleEndian);
  dv.setUint32(20, opts.network >>> 0, opts.littleEndian);
  return header;
};

const makeRecord = (opts: {
  littleEndian: boolean;
  tsSec: number;
  tsSubsec: number;
  capturedLength: number;
  originalLength: number;
  payload: Uint8Array;
}): Uint8Array => {
  const header = new Uint8Array(16);
  const dv = new DataView(header.buffer);
  dv.setUint32(0, opts.tsSec >>> 0, opts.littleEndian);
  dv.setUint32(4, opts.tsSubsec >>> 0, opts.littleEndian);
  dv.setUint32(8, opts.capturedLength >>> 0, opts.littleEndian);
  dv.setUint32(12, opts.originalLength >>> 0, opts.littleEndian);
  return concatParts([header, opts.payload]);
};

void test("parsePcap parses global header, packet stats, and protocol breakdown", async () => {
  const file = createPcapFile();
  const parsed = await parsePcap(file);
  assert.ok(parsed);

  assert.strictEqual(parsed.isPcap, true);
  assert.strictEqual(parsed.fileSize, file.size);
  assert.strictEqual(parsed.header.littleEndian, true);
  assert.strictEqual(parsed.header.timestampResolution, "microseconds");
  assert.strictEqual(parsed.header.network, 1);
  assert.match(parsed.header.networkName || "", /ethernet/i);

  assert.strictEqual(parsed.packets.totalPackets, 3);
  assert.strictEqual(parsed.packets.truncatedPackets, 1);
  assert.strictEqual(parsed.packets.totalCapturedBytes > 0, true);

  const eth = parsed.linkLayer?.ethernet;
  assert.ok(eth);
  assert.strictEqual(eth.framesParsed, 3);
  assert.strictEqual(eth.etherTypes.get(0x0800) || 0, 1);
  assert.strictEqual(eth.etherTypes.get(0x86dd) || 0, 1);
  assert.strictEqual(eth.etherTypes.get(0x0806) || 0, 1);
  assert.strictEqual(eth.ipProtocols.get(6) || 0, 1);
  assert.strictEqual(eth.ipProtocols.get(17) || 0, 1);
});

void test("parsePcap supports big-endian PCAP files", async () => {
  const file = createPcapBigEndianFile();
  const parsed = await parsePcap(file);
  assert.ok(parsed);
  assert.strictEqual(parsed.header.littleEndian, false);
  assert.strictEqual(parsed.packets.totalPackets, 1);
});

void test("parsePcap returns null for non-PCAP signatures", async () => {
  const file = new MockFile(new Uint8Array([0x00, 0x01, 0x02, 0x03]), "not.pcap");
  const parsed = await parsePcap(file);
  assert.equal(parsed, null);
});

void test("parsePcap reports truncation when record data runs past EOF", async () => {
  const bytes = new Uint8Array(24 + 16);
  const dv = new DataView(bytes.buffer);
  dv.setUint32(0, 0xa1b2c3d4, true);
  dv.setUint16(4, 2, true);
  dv.setUint16(6, 4, true);
  dv.setUint32(16, 65535, true);
  dv.setUint32(20, 1, true);
  dv.setUint32(24 + 8, 100, true);
  dv.setUint32(24 + 12, 100, true);
  const file = new MockFile(bytes, "truncated.pcap");
  const parsed = await parsePcap(file);
  assert.ok(parsed);
  assert.ok(parsed.issues.length >= 1);
  assert.strictEqual(parsed.packets.truncatedFile, true);
});

void test("parsePcap supports nanosecond timestamps and unknown link types", async () => {
  const global = makeGlobalHeader({
    littleEndian: false,
    nanoseconds: true,
    versionMajor: 2,
    versionMinor: 3,
    snaplen: 32,
    network: 999
  });
  const file = new MockFile(global, "nano.pcap");
  const parsed = await parsePcap(file);
  assert.ok(parsed);
  assert.strictEqual(parsed.header.littleEndian, false);
  assert.strictEqual(parsed.header.timestampResolution, "nanoseconds");
  assert.strictEqual(parsed.header.network, 999);
  assert.match(parsed.header.networkName || "", /999/);
  assert.strictEqual(parsed.linkLayer, null);
  assert.strictEqual(parsed.packets.totalPackets, 0);
  assert.strictEqual(parsed.packets.capturedLengthAverage, null);
  assert.ok(parsed.issues.some(issue => issue.includes("Unusual PCAP version")));
});

void test("parsePcap parses VLAN-tagged Ethernet frames", async () => {
  const littleEndian = true;
  const global = makeGlobalHeader({ littleEndian, snaplen: 65535, network: 1 });

  const vlanIpv4 = new Uint8Array(18 + 20).fill(0);
  vlanIpv4[12] = 0x81;
  vlanIpv4[13] = 0x00;
  vlanIpv4[14] = 0x00;
  vlanIpv4[15] = 0x01;
  vlanIpv4[16] = 0x08;
  vlanIpv4[17] = 0x00;
  vlanIpv4[18] = 0x45;
  vlanIpv4[27] = 17;

  const record = makeRecord({
    littleEndian,
    tsSec: 1,
    tsSubsec: 0,
    capturedLength: vlanIpv4.length,
    originalLength: vlanIpv4.length,
    payload: vlanIpv4
  });

  const file = new MockFile(concatParts([global, record]), "vlan.pcap");
  const parsed = await parsePcap(file);
  assert.ok(parsed);
  const eth = parsed.linkLayer?.ethernet;
  assert.ok(eth);
  assert.strictEqual(eth.vlanTaggedFrames, 1);
  assert.strictEqual(eth.framesParsed, 1);
  assert.strictEqual(eth.etherTypes.get(0x0800) || 0, 1);
  assert.strictEqual(eth.ipProtocols.get(17) || 0, 1);
});

void test("parsePcap counts short Ethernet frames", async () => {
  const littleEndian = true;
  const global = makeGlobalHeader({ littleEndian, snaplen: 65535, network: 1 });
  const payload = new Uint8Array(10).fill(0);
  const record = makeRecord({
    littleEndian,
    tsSec: 1,
    tsSubsec: 0,
    capturedLength: payload.length,
    originalLength: payload.length,
    payload
  });
  const file = new MockFile(concatParts([global, record]), "short-ethernet.pcap");
  const parsed = await parsePcap(file);
  assert.ok(parsed);
  const eth = parsed.linkLayer?.ethernet;
  assert.ok(eth);
  assert.strictEqual(eth.shortFrames, 1);
  assert.strictEqual(eth.framesParsed, 0);
});

void test("parsePcap warns when captured length exceeds snaplen", async () => {
  const littleEndian = true;
  const global = makeGlobalHeader({ littleEndian, snaplen: 10, network: 1 });
  const payload = new Uint8Array(20).fill(0);
  payload[12] = 0x08;
  payload[13] = 0x06;
  const record = makeRecord({
    littleEndian,
    tsSec: 1,
    tsSubsec: 0,
    capturedLength: payload.length,
    originalLength: payload.length,
    payload
  });
  const file = new MockFile(concatParts([global, record]), "snaplen.pcap");
  const parsed = await parsePcap(file);
  assert.ok(parsed);
  assert.ok(parsed.issues.some(issue => issue.includes("exceeds snaplen")));
});

void test("parsePcap warns when captured length exceeds original length", async () => {
  const littleEndian = true;
  const global = makeGlobalHeader({ littleEndian, snaplen: 65535, network: 1 });
  const payload = new Uint8Array(20).fill(0);
  payload[12] = 0x08;
  payload[13] = 0x00;
  const record = makeRecord({
    littleEndian,
    tsSec: 1,
    tsSubsec: 0,
    capturedLength: payload.length,
    originalLength: payload.length - 5,
    payload
  });
  const file = new MockFile(concatParts([global, record]), "bad-len.pcap");
  const parsed = await parsePcap(file);
  assert.ok(parsed);
  assert.ok(parsed.issues.some(issue => issue.includes("larger than original length")));
});

void test("parsePcap counts out-of-order timestamps", async () => {
  const littleEndian = true;
  const global = makeGlobalHeader({ littleEndian, snaplen: 65535, network: 1 });

  const ipv4Short = new Uint8Array(14).fill(0);
  ipv4Short[12] = 0x08;
  ipv4Short[13] = 0x00;
  const ipv6Short = new Uint8Array(14).fill(0);
  ipv6Short[12] = 0x86;
  ipv6Short[13] = 0xdd;

  const record1 = makeRecord({
    littleEndian,
    tsSec: 10,
    tsSubsec: 0,
    capturedLength: ipv4Short.length,
    originalLength: ipv4Short.length,
    payload: ipv4Short
  });
  const record2 = makeRecord({
    littleEndian,
    tsSec: 9,
    tsSubsec: 0,
    capturedLength: ipv6Short.length,
    originalLength: ipv6Short.length,
    payload: ipv6Short
  });

  const file = new MockFile(concatParts([global, record1, record2]), "timestamps.pcap");
  const parsed = await parsePcap(file);
  assert.ok(parsed);
  assert.strictEqual(parsed.packets.outOfOrderTimestamps, 1);

  const eth = parsed.linkLayer?.ethernet;
  assert.ok(eth);
  assert.strictEqual(eth.framesParsed, 2);
  assert.strictEqual(eth.ipProtocols.size, 0);
});

void test("parsePcap reports truncation when trailing bytes remain after the last record", async () => {
  const littleEndian = true;
  const global = makeGlobalHeader({ littleEndian, snaplen: 65535, network: 1 });
  const record = makeRecord({
    littleEndian,
    tsSec: 1,
    tsSubsec: 0,
    capturedLength: 0,
    originalLength: 0,
    payload: new Uint8Array(0)
  });
  const file = new MockFile(
    concatParts([global, record, new Uint8Array([0x01, 0x02, 0x03, 0x04, 0x05])]),
    "trailing.pcap"
  );
  const parsed = await parsePcap(file);
  assert.ok(parsed);
  assert.strictEqual(parsed.packets.truncatedFile, true);
  assert.ok(parsed.issues.some(issue => issue.includes("trailing bytes")));
});
