"use strict";

import type { FileRangeReader } from "../file-range-reader.js";
import { LINKTYPE_ETHERNET } from "../capture/link-types.js";
import type { PcapLinkLayerSummary } from "../capture/types.js";
import type { MutableTrafficStats } from "../capture/stats.js";
import type { PcapNgBlockSummary, PcapNgInterfaceStatistics, PcapNgNameResolutionSummary } from "./types.js";
import type { PcapNgOption } from "./options.js";
import { readUint64Option } from "./options.js";

// A pcapng block begins with 8 octets (Block Type + Block Total Length); SHB parsing
// needs the next 4 octets as well to read the Byte-Order Magic.
// Source: draft-ietf-opsawg-pcapng-05 Section 3.1 and Section 4.1 Figure 9,
// https://datatracker.ietf.org/doc/draft-ietf-opsawg-pcapng/
export const BLOCK_PREFIX_BYTES = 8;
export const BLOCK_HEADER_BYTES = 12;
export const BLOCK_TRAILER_BYTES = 4;

// Fixed per-block header sizes:
// EPB is 28 octets (Section 4.3 Figure 11), SPB is 12 octets (Section 4.4 Figure 13),
// and the obsolete Packet Block is 28 octets (Appendix A Figure 20).
// Source: https://datatracker.ietf.org/doc/draft-ietf-opsawg-pcapng/
export const ENHANCED_PACKET_HEADER_BYTES = 28;
export const SIMPLE_PACKET_HEADER_BYTES = 12;
export const LEGACY_PACKET_HEADER_BYTES = 28;
export const PCAPNG_ALIGNMENT_BYTES = 4;
export const MAX_SAFE_BIGINT = BigInt(Number.MAX_SAFE_INTEGER);

// Standard block type codes.
// Source: draft-ietf-opsawg-pcapng-05 Section 10.1 and Sections 4.1-4.8,
// https://datatracker.ietf.org/doc/draft-ietf-opsawg-pcapng/
export const SHB_TYPE = 0x0a0d0d0a;
export const IDB_TYPE = 0x00000001;
export const PACKET_BLOCK_TYPE = 0x00000002;
export const SIMPLE_PACKET_BLOCK_TYPE = 0x00000003;
export const NAME_RESOLUTION_BLOCK_TYPE = 0x00000004;
export const INTERFACE_STATISTICS_BLOCK_TYPE = 0x00000005;
export const ENHANCED_PACKET_BLOCK_TYPE = 0x00000006;
export const DECRYPTION_SECRETS_BLOCK_TYPE = 0x0000000a;
export const CUSTOM_BLOCK_COPYABLE_TYPE = 0x00000bad;
export const CUSTOM_BLOCK_NOCOPY_TYPE = 0x40000bad;

// Section Header Block Byte-Order Magic values.
// Source: draft-ietf-opsawg-pcapng-05 Section 4.1 Figure 9,
// https://datatracker.ietf.org/doc/draft-ietf-opsawg-pcapng/
const BYTE_ORDER_MAGIC = 0x1a2b3c4d;
const BYTE_ORDER_MAGIC_SWAPPED = 0x4d3c2b1a;

// Name Resolution Block record codes.
// Source: draft-ietf-opsawg-pcapng-05 Section 4.5 Table 6,
// https://datatracker.ietf.org/doc/draft-ietf-opsawg-pcapng/
export const NRB_RECORD_END = 0x0000;
export const NRB_RECORD_IPV4 = 0x0001;
export const NRB_RECORD_IPV6 = 0x0002;

export type InterfaceState = {
  sectionIndex: number;
  interfaceId: number;
  linkType: number;
  linkTypeName: string;
  snaplen: number;
  name: string | null;
  description: string | null;
  hardware: string | null;
  os: string | null;
  filter: string | null;
  timestampResolution: string;
  unitsPerSecond: number;
  timestampOffsetSeconds: bigint | null;
  observedDropCount: bigint | null;
  statistics: PcapNgInterfaceStatistics | null;
  traffic: MutableTrafficStats;
};

export type SectionState = {
  index: number;
  littleEndian: boolean;
  interfaces: InterfaceState[];
};

export const createBlockSummary = (): PcapNgBlockSummary => ({
  totalBlocks: 0,
  interfaceDescriptionBlocks: 0,
  enhancedPacketBlocks: 0,
  simplePacketBlocks: 0,
  packetBlocks: 0,
  nameResolutionBlocks: 0,
  interfaceStatisticsBlocks: 0,
  decryptionSecretsBlocks: 0,
  customBlocks: 0,
  unknownBlocks: 0
});

export const createNameResolutionSummary = (): PcapNgNameResolutionSummary => ({
  ipv4Records: 0,
  ipv6Records: 0,
  otherRecords: 0,
  missingEndMarkers: 0
});

export const formatOffset = (offset: number): string => `0x${offset.toString(16)}`;

export const readBigInt64 = (
  dv: DataView,
  offset: number,
  littleEndian: boolean
): bigint | null => {
  if (offset + 8 > dv.byteLength) return null;
  return dv.getBigInt64(offset, littleEndian);
};

export const readSectionEndianness = (header: DataView): boolean | null => {
  if (header.byteLength < BLOCK_HEADER_BYTES) return null;
  const rawMagic = header.getUint32(8, false);
  if (rawMagic === BYTE_ORDER_MAGIC) return false;
  if (rawMagic === BYTE_ORDER_MAGIC_SWAPPED) return true;
  return null;
};

export const readBlockTailLength = async (
  reader: FileRangeReader,
  blockEnd: number,
  littleEndian: boolean
): Promise<number | null> => {
  if (blockEnd < BLOCK_TRAILER_BYTES) return null;
  const tail = await reader.read(blockEnd - BLOCK_TRAILER_BYTES, BLOCK_TRAILER_BYTES);
  return tail.byteLength < BLOCK_TRAILER_BYTES ? null : tail.getUint32(0, littleEndian);
};

export const readMetadataBlock = async (
  reader: FileRangeReader,
  offset: number,
  blockLength: number
): Promise<DataView> =>
  reader.read(offset, blockLength);

export const joinUint64 = (upper: number, lower: number): bigint =>
  (BigInt(upper >>> 0) << 32n) | BigInt(lower >>> 0);

export const getTimestampSeconds = (
  interfaceState: InterfaceState | null,
  upper: number,
  lower: number,
  pushIssue: (message: string) => void,
  contextLabel: string
): number | null => {
  if (!interfaceState) return null;
  if (interfaceState.timestampOffsetSeconds == null) {
    pushIssue(`${contextLabel} depends on an invalid if_tsoffset value and cannot be represented exactly.`);
    return null;
  }
  if (interfaceState.unitsPerSecond <= 0 || !Number.isFinite(interfaceState.unitsPerSecond)) {
    pushIssue(`${contextLabel} has a timestamp that cannot be represented precisely in JavaScript.`);
    return null;
  }
  const raw = joinUint64(upper, lower);
  if (
    raw > MAX_SAFE_BIGINT ||
    interfaceState.timestampOffsetSeconds < -MAX_SAFE_BIGINT ||
    interfaceState.timestampOffsetSeconds > MAX_SAFE_BIGINT
  ) {
    pushIssue(`${contextLabel} has a timestamp that cannot be represented precisely in JavaScript.`);
    return null;
  }
  const seconds =
    Number(raw) / interfaceState.unitsPerSecond + Number(interfaceState.timestampOffsetSeconds);
  if (Number.isFinite(seconds)) return seconds;
  pushIssue(`${contextLabel} has a timestamp that cannot be represented precisely in JavaScript.`);
  return null;
};

export const addObservedDropCount = (interfaceState: InterfaceState | null, amount: bigint | null): void => {
  if (!interfaceState || amount == null) return;
  interfaceState.observedDropCount = (interfaceState.observedDropCount || 0n) + amount;
};

export const findOption = (options: PcapNgOption[], code: number): PcapNgOption | null =>
  options.find(option => option.code === code) || null;

export const readUint64OptionValue = (
  options: PcapNgOption[],
  code: number,
  littleEndian: boolean,
  pushIssue: (message: string) => void,
  contextLabel: string
): bigint | null => {
  const option = findOption(options, code);
  if (!option) return null;
  const value = readUint64Option(option, littleEndian);
  if (value != null) return value;
  pushIssue(`${contextLabel} option ${code} does not contain an 8-byte integer.`);
  return null;
};

export const isEthernetLinkType = (linkType: number): boolean =>
  linkType === LINKTYPE_ETHERNET;

export const getEthernetSummary = (linkLayer: PcapLinkLayerSummary | null) =>
  linkLayer?.ethernet || null;
