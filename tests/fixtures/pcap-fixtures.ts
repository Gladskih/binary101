"use strict";

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

const makeGlobalHeader = (opts: { littleEndian: boolean; nanoseconds: boolean; network: number; snaplen: number }) => {
  const header = new Uint8Array(24);
  const dv = new DataView(header.buffer);
  const magic = opts.nanoseconds ? 0xa1b23c4d : 0xa1b2c3d4;
  dv.setUint32(0, magic, opts.littleEndian);
  dv.setUint16(4, 2, opts.littleEndian);
  dv.setUint16(6, 4, opts.littleEndian);
  dv.setInt32(8, 0, opts.littleEndian);
  dv.setUint32(12, 0, opts.littleEndian);
  dv.setUint32(16, opts.snaplen >>> 0, opts.littleEndian);
  dv.setUint32(20, opts.network >>> 0, opts.littleEndian);
  return header;
};

const makeRecord = (
  opts: {
    littleEndian: boolean;
    tsSec: number;
    tsSubsec: number;
    capturedLength: number;
    originalLength: number;
    payload: Uint8Array;
  }
): Uint8Array => {
  const header = new Uint8Array(16);
  const dv = new DataView(header.buffer);
  dv.setUint32(0, opts.tsSec >>> 0, opts.littleEndian);
  dv.setUint32(4, opts.tsSubsec >>> 0, opts.littleEndian);
  dv.setUint32(8, opts.capturedLength >>> 0, opts.littleEndian);
  dv.setUint32(12, opts.originalLength >>> 0, opts.littleEndian);
  return concatParts([header, opts.payload]);
};

const makeEthernetFrame = (etherType: number, payload: Uint8Array): Uint8Array => {
  const header = new Uint8Array(14);
  header.set([0x00, 0x11, 0x22, 0x33, 0x44, 0x55], 0);
  header.set([0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb], 6);
  header[12] = (etherType >>> 8) & 0xff;
  header[13] = etherType & 0xff;
  return concatParts([header, payload]);
};

const makeIpv4Header = (protocol: number): Uint8Array => {
  const header = new Uint8Array(20).fill(0);
  header[0] = 0x45;
  header[9] = protocol & 0xff;
  return header;
};

const makeIpv6Header = (nextHeader: number): Uint8Array => {
  const header = new Uint8Array(40).fill(0);
  header[0] = 0x60;
  header[6] = nextHeader & 0xff;
  return header;
};

export const createPcapFile = (): MockFile => {
  const littleEndian = true;
  const global = makeGlobalHeader({ littleEndian, nanoseconds: false, network: 1, snaplen: 65535 });

  const ipv4Tcp = makeEthernetFrame(0x0800, makeIpv4Header(6));
  const ipv6Udp = makeEthernetFrame(0x86dd, makeIpv6Header(17));
  const arp = makeEthernetFrame(0x0806, new Uint8Array(28).fill(0));

  const t0 = 1700000000;
  const records = [
    makeRecord({
      littleEndian,
      tsSec: t0,
      tsSubsec: 123456,
      capturedLength: ipv4Tcp.length,
      originalLength: ipv4Tcp.length + 20,
      payload: ipv4Tcp
    }),
    makeRecord({
      littleEndian,
      tsSec: t0 + 1,
      tsSubsec: 1,
      capturedLength: ipv6Udp.length,
      originalLength: ipv6Udp.length,
      payload: ipv6Udp
    }),
    makeRecord({
      littleEndian,
      tsSec: t0 + 2,
      tsSubsec: 0,
      capturedLength: arp.length,
      originalLength: arp.length,
      payload: arp
    })
  ];

  const bytes = concatParts([global, ...records]);
  return new MockFile(bytes, "sample.pcap", "application/vnd.tcpdump.pcap");
};

export const createPcapBigEndianFile = (): MockFile => {
  const littleEndian = false;
  const global = makeGlobalHeader({ littleEndian, nanoseconds: false, network: 1, snaplen: 65535 });
  const ipv4Udp = makeEthernetFrame(0x0800, makeIpv4Header(17));
  const record = makeRecord({
    littleEndian,
    tsSec: 1700000000,
    tsSubsec: 999999,
    capturedLength: ipv4Udp.length,
    originalLength: ipv4Udp.length,
    payload: ipv4Udp
  });
  const bytes = concatParts([global, record]);
  return new MockFile(bytes, "sample-be.pcap", "application/octet-stream");
};

