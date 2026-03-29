"use strict";

import { alignUpTo } from "../../binary-utils.js";

const SHB_TYPE = 0x0a0d0d0a;
const IDB_TYPE = 0x00000001;
const PACKET_BLOCK_TYPE = 0x00000002;
const SIMPLE_PACKET_BLOCK_TYPE = 0x00000003;
const NAME_RESOLUTION_BLOCK_TYPE = 0x00000004;
const INTERFACE_STATISTICS_BLOCK_TYPE = 0x00000005;
const ENHANCED_PACKET_BLOCK_TYPE = 0x00000006;
const DECRYPTION_SECRETS_BLOCK_TYPE = 0x0000000a;
const CUSTOM_BLOCK_COPYABLE_TYPE = 0x00000bad;
const BYTE_ORDER_MAGIC = 0x1a2b3c4d;

const encoder = new TextEncoder();

export const concatParts = (parts: Uint8Array[]): Uint8Array => {
  const total = parts.reduce((sum, part) => sum + part.length, 0);
  const out = new Uint8Array(total);
  let cursor = 0;
  for (const part of parts) {
    out.set(part, cursor);
    cursor += part.length;
  }
  return out;
};

const u16 = (value: number, littleEndian: boolean): Uint8Array => {
  const bytes = new Uint8Array(2);
  new DataView(bytes.buffer).setUint16(0, value, littleEndian);
  return bytes;
};

const u32 = (value: number, littleEndian: boolean): Uint8Array => {
  const bytes = new Uint8Array(4);
  new DataView(bytes.buffer).setUint32(0, value >>> 0, littleEndian);
  return bytes;
};

const u64 = (value: bigint, littleEndian: boolean): Uint8Array => {
  const bytes = new Uint8Array(8);
  new DataView(bytes.buffer).setBigUint64(0, value, littleEndian);
  return bytes;
};

const i64 = (value: bigint, littleEndian: boolean): Uint8Array => {
  const bytes = new Uint8Array(8);
  new DataView(bytes.buffer).setBigInt64(0, value, littleEndian);
  return bytes;
};

const pad4 = (value: Uint8Array): Uint8Array => {
  const paddedLength = alignUpTo(value.length, 4);
  if (paddedLength === value.length) return value;
  const padded = new Uint8Array(paddedLength);
  padded.set(value);
  return padded;
};

const makeOption = (code: number, value: Uint8Array, littleEndian: boolean): Uint8Array =>
  concatParts([u16(code, littleEndian), u16(value.length, littleEndian), pad4(value)]);

const makeOptions = (
  options: Array<{ code: number; value: Uint8Array }>,
  littleEndian: boolean
): Uint8Array =>
  concatParts([...options.map(option => makeOption(option.code, option.value, littleEndian)), new Uint8Array(4)]);

const makeBlock = (type: number, body: Uint8Array, littleEndian: boolean): Uint8Array => {
  const totalLength = 12 + body.length;
  return concatParts([u32(type, littleEndian), u32(totalLength, littleEndian), body, u32(totalLength, littleEndian)]);
};

export const makeSectionHeader = (opts: {
  littleEndian: boolean;
  hardware?: string;
  os?: string;
  userAppl?: string;
  versionMinor?: number;
}): Uint8Array => {
  const options = makeOptions(
    [
      opts.hardware ? { code: 2, value: encoder.encode(opts.hardware) } : null,
      opts.os ? { code: 3, value: encoder.encode(opts.os) } : null,
      opts.userAppl ? { code: 4, value: encoder.encode(opts.userAppl) } : null
    ].filter(Boolean) as Array<{ code: number; value: Uint8Array }>,
    opts.littleEndian
  );
  return makeBlock(
    SHB_TYPE,
    concatParts([
      u32(BYTE_ORDER_MAGIC, opts.littleEndian),
      u16(1, opts.littleEndian),
      u16(opts.versionMinor ?? 0, opts.littleEndian),
      i64(-1n, opts.littleEndian),
      options
    ]),
    opts.littleEndian
  );
};

export const makeInterfaceDescription = (opts: {
  littleEndian: boolean;
  linkType: number;
  snaplen: number;
  name?: string;
  description?: string;
  tsresol?: number;
  tsoffsetSeconds?: bigint;
  filter?: string;
  os?: string;
  hardware?: string;
}): Uint8Array => {
  const options = makeOptions(
    [
      opts.name ? { code: 2, value: encoder.encode(opts.name) } : null,
      opts.description ? { code: 3, value: encoder.encode(opts.description) } : null,
      opts.tsresol != null ? { code: 9, value: new Uint8Array([opts.tsresol]) } : null,
      opts.filter ? { code: 11, value: concatParts([new Uint8Array([0]), encoder.encode(opts.filter)]) } : null,
      opts.os ? { code: 12, value: encoder.encode(opts.os) } : null,
      opts.tsoffsetSeconds != null ? { code: 14, value: i64(opts.tsoffsetSeconds, opts.littleEndian) } : null,
      opts.hardware ? { code: 15, value: encoder.encode(opts.hardware) } : null
    ].filter(Boolean) as Array<{ code: number; value: Uint8Array }>,
    opts.littleEndian
  );
  return makeBlock(
    IDB_TYPE,
    concatParts([
      u16(opts.linkType, opts.littleEndian),
      u16(0, opts.littleEndian),
      u32(opts.snaplen, opts.littleEndian),
      options
    ]),
    opts.littleEndian
  );
};

export const makeEnhancedPacketBlock = (opts: {
  littleEndian: boolean;
  interfaceId: number;
  timestamp: bigint;
  payload: Uint8Array;
  originalLength: number;
  dropCount?: bigint;
}): Uint8Array => {
  const upper = Number((opts.timestamp >> 32n) & 0xffffffffn);
  const lower = Number(opts.timestamp & 0xffffffffn);
  const options = makeOptions(
    opts.dropCount != null ? [{ code: 4, value: u64(opts.dropCount, opts.littleEndian) }] : [],
    opts.littleEndian
  );
  return makeBlock(
    ENHANCED_PACKET_BLOCK_TYPE,
    concatParts([
      u32(opts.interfaceId, opts.littleEndian),
      u32(upper, opts.littleEndian),
      u32(lower, opts.littleEndian),
      u32(opts.payload.length, opts.littleEndian),
      u32(opts.originalLength, opts.littleEndian),
      pad4(opts.payload),
      options
    ]),
    opts.littleEndian
  );
};

export const makeSimplePacketBlock = (opts: {
  littleEndian: boolean;
  payload: Uint8Array;
  originalLength: number;
}): Uint8Array =>
  makeBlock(
    SIMPLE_PACKET_BLOCK_TYPE,
    concatParts([u32(opts.originalLength, opts.littleEndian), pad4(opts.payload)]),
    opts.littleEndian
  );

export const makePacketBlock = (opts: {
  littleEndian: boolean;
  interfaceId: number;
  dropsCount: number;
  timestamp: bigint;
  payload: Uint8Array;
  originalLength: number;
}): Uint8Array => {
  const upper = Number((opts.timestamp >> 32n) & 0xffffffffn);
  const lower = Number(opts.timestamp & 0xffffffffn);
  return makeBlock(
    PACKET_BLOCK_TYPE,
    concatParts([
      u16(opts.interfaceId, opts.littleEndian),
      u16(opts.dropsCount, opts.littleEndian),
      u32(upper, opts.littleEndian),
      u32(lower, opts.littleEndian),
      u32(opts.payload.length, opts.littleEndian),
      u32(opts.originalLength, opts.littleEndian),
      pad4(opts.payload),
      new Uint8Array(4)
    ]),
    opts.littleEndian
  );
};

export const makeNameResolutionBlock = (littleEndian: boolean): Uint8Array => {
  const ipv4RecordValue = pad4(concatParts([new Uint8Array([192, 0, 2, 1]), encoder.encode("host\0")]));
  const ipv6RecordValue = pad4(
    concatParts([new Uint8Array(16).fill(0x20), new Uint8Array([64]), encoder.encode("ipv6\0")])
  );
  return makeBlock(
    NAME_RESOLUTION_BLOCK_TYPE,
    concatParts([
      u16(1, littleEndian),
      u16(9, littleEndian),
      ipv4RecordValue,
      u16(2, littleEndian),
      u16(22, littleEndian),
      ipv6RecordValue,
      new Uint8Array(4),
      new Uint8Array(4)
    ]),
    littleEndian
  );
};

export const makeInterfaceStatisticsBlock = (opts: {
  littleEndian: boolean;
  interfaceId: number;
  timestamp: bigint;
  captureStart: bigint;
  captureEnd: bigint;
  receivedPackets: bigint;
  droppedByInterface: bigint;
  deliveredToUser: bigint;
}): Uint8Array => {
  const upper = Number((opts.timestamp >> 32n) & 0xffffffffn);
  const lower = Number(opts.timestamp & 0xffffffffn);
  const options = makeOptions(
    [
      { code: 2, value: u64(opts.captureStart, opts.littleEndian) },
      { code: 3, value: u64(opts.captureEnd, opts.littleEndian) },
      { code: 4, value: u64(opts.receivedPackets, opts.littleEndian) },
      { code: 5, value: u64(opts.droppedByInterface, opts.littleEndian) },
      { code: 8, value: u64(opts.deliveredToUser, opts.littleEndian) }
    ],
    opts.littleEndian
  );
  return makeBlock(
    INTERFACE_STATISTICS_BLOCK_TYPE,
    concatParts([
      u32(opts.interfaceId, opts.littleEndian),
      u32(upper, opts.littleEndian),
      u32(lower, opts.littleEndian),
      options
    ]),
    opts.littleEndian
  );
};

export const makeDecryptionSecretsBlock = (littleEndian: boolean): Uint8Array =>
  makeBlock(
    DECRYPTION_SECRETS_BLOCK_TYPE,
    concatParts([u32(0, littleEndian), u32(0, littleEndian)]),
    littleEndian
  );

export const makeCustomBlock = (littleEndian: boolean): Uint8Array =>
  makeBlock(
    CUSTOM_BLOCK_COPYABLE_TYPE,
    concatParts([u32(32473, littleEndian), new Uint8Array([1, 2, 3, 4])]),
    littleEndian
  );

export const makeEthernetFrame = (etherType: number, payload: Uint8Array): Uint8Array => {
  const header = new Uint8Array(14);
  header.set([0, 1, 2, 3, 4, 5], 0);
  header.set([6, 7, 8, 9, 10, 11], 6);
  header[12] = (etherType >>> 8) & 0xff;
  header[13] = etherType & 0xff;
  return concatParts([header, payload]);
};

export const makeIpv4Header = (protocol: number): Uint8Array => {
  const header = new Uint8Array(20).fill(0);
  header[0] = 0x45;
  header[9] = protocol;
  return header;
};

export const makeIpv6Header = (nextHeader: number): Uint8Array => {
  const header = new Uint8Array(40).fill(0);
  header[0] = 0x60;
  header[6] = nextHeader;
  return header;
};
