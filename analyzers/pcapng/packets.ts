"use strict";

import type { FileRangeReader } from "../file-range-reader.js";
import { alignUpTo } from "../../binary-utils.js";
import { analyzeEthernetSample } from "../capture/payload-analysis.js";
import type { PcapLinkLayerSummary } from "../capture/types.js";
import type { MutableTrafficStats } from "../capture/stats.js";
import { observePacket } from "../capture/stats.js";
import type { InterfaceState, SectionState } from "./shared.js";
import {
  BLOCK_TRAILER_BYTES,
  ENHANCED_PACKET_HEADER_BYTES,
  LEGACY_PACKET_HEADER_BYTES,
  PCAPNG_ALIGNMENT_BYTES,
  SIMPLE_PACKET_HEADER_BYTES,
  addObservedDropCount,
  formatOffset,
  getEthernetSummary,
  getTimestampSeconds,
  isEthernetLinkType,
  readUint64OptionValue
} from "./shared.js";
import { parsePcapNgOptions, type PcapNgOption } from "./options.js";

const updatePacketStats = (
  globalTraffic: MutableTrafficStats,
  interfaceState: InterfaceState | null,
  capturedLength: number,
  originalLength: number,
  timestampSeconds: number | null,
  packetSample: Uint8Array,
  linkLayer: PcapLinkLayerSummary | null,
  pushIssue: (message: string) => void,
  packetNumber: number
): void => {
  if (originalLength < capturedLength) {
    pushIssue(
      `Packet #${packetNumber} has captured length (${capturedLength}) larger than original length (${originalLength}).`
    );
  }
  if (interfaceState && interfaceState.snaplen > 0 && capturedLength > interfaceState.snaplen) {
    pushIssue(
      `Packet #${packetNumber} captured length (${capturedLength}) exceeds interface snaplen (${interfaceState.snaplen}).`
    );
  }
  observePacket(globalTraffic, capturedLength, originalLength, timestampSeconds);
  if (interfaceState) observePacket(interfaceState.traffic, capturedLength, originalLength, timestampSeconds);
  if (interfaceState && isEthernetLinkType(interfaceState.linkType)) {
    analyzeEthernetSample(packetSample, getEthernetSummary(linkLayer));
  }
};

const readPacketOptions = (
  blockView: DataView,
  optionsOffsetInBlock: number,
  littleEndian: boolean,
  pushIssue: (message: string) => void,
  contextLabel: string
): PcapNgOption[] => {
  if (optionsOffsetInBlock > blockView.byteLength - BLOCK_TRAILER_BYTES) {
    pushIssue(`${contextLabel} has packet data that overlaps the block trailer.`);
    return [];
  }
  if (optionsOffsetInBlock === blockView.byteLength - BLOCK_TRAILER_BYTES) return [];
  return parsePcapNgOptions(
    blockView,
    optionsOffsetInBlock,
    blockView.byteLength - BLOCK_TRAILER_BYTES,
    littleEndian,
    pushIssue,
    contextLabel
  );
};

export const parseEnhancedPacketBlock = async (
  reader: FileRangeReader,
  offset: number,
  blockLength: number,
  section: SectionState,
  globalTraffic: MutableTrafficStats,
  linkLayer: PcapLinkLayerSummary | null,
  pushIssue: (message: string) => void
): Promise<void> => {
  const blockView = await reader.read(offset, blockLength);
  // EPB fixed fields: Interface ID at octet 8, split timestamp at 12/16,
  // Captured Packet Length at 20, Original Packet Length at 24.
  // Source: draft-ietf-opsawg-pcapng-05 Section 4.3 Figure 11,
  // https://datatracker.ietf.org/doc/draft-ietf-opsawg-pcapng/
  if (blockView.byteLength < ENHANCED_PACKET_HEADER_BYTES) {
    pushIssue(`Enhanced Packet Block at ${formatOffset(offset)} is truncated.`);
    return;
  }
  const interfaceId = blockView.getUint32(8, section.littleEndian);
  const interfaceState = section.interfaces[interfaceId] || null;
  if (!interfaceState) {
    pushIssue(`Enhanced Packet Block at ${formatOffset(offset)} references missing interface ${interfaceId}.`);
  }
  const capturedLength = blockView.getUint32(20, section.littleEndian);
  const originalLength = blockView.getUint32(24, section.littleEndian);
  const packetNumber = globalTraffic.totalPackets + 1;
  const packetBytesAvailable = Math.max(
    0,
    blockView.byteLength - ENHANCED_PACKET_HEADER_BYTES - BLOCK_TRAILER_BYTES
  );
  const packetSample = new Uint8Array(
    blockView.buffer,
    blockView.byteOffset + ENHANCED_PACKET_HEADER_BYTES,
    Math.min(capturedLength, packetBytesAvailable)
  );
  updatePacketStats(
    globalTraffic,
    interfaceState,
    capturedLength,
    originalLength,
    getTimestampSeconds(
      interfaceState,
      blockView.getUint32(12, section.littleEndian),
      blockView.getUint32(16, section.littleEndian),
      pushIssue,
      `Enhanced Packet Block at ${formatOffset(offset)}`
    ),
    packetSample,
    linkLayer,
    pushIssue,
    packetNumber
  );
  const options = readPacketOptions(
    blockView,
    ENHANCED_PACKET_HEADER_BYTES + alignUpTo(capturedLength, PCAPNG_ALIGNMENT_BYTES),
    section.littleEndian,
    pushIssue,
    `Enhanced Packet Block at ${formatOffset(offset)}`
  );
  // epb_dropcount has option code 4.
  // Source: draft-ietf-opsawg-pcapng-05 Section 4.3 Table 4,
  // https://datatracker.ietf.org/doc/draft-ietf-opsawg-pcapng/
  addObservedDropCount(
    interfaceState,
    readUint64OptionValue(options, 4, section.littleEndian, pushIssue, `Enhanced Packet Block at ${formatOffset(offset)}`)
  );
};

export const parseSimplePacketBlock = async (
  reader: FileRangeReader,
  offset: number,
  blockLength: number,
  section: SectionState,
  globalTraffic: MutableTrafficStats,
  linkLayer: PcapLinkLayerSummary | null,
  pushIssue: (message: string) => void
): Promise<void> => {
  const blockView = await reader.read(offset, blockLength);
  if (blockView.byteLength < SIMPLE_PACKET_HEADER_BYTES) {
    pushIssue(`Simple Packet Block at ${formatOffset(offset)} is truncated.`);
    return;
  }
  // SPB has no Interface ID; it always refers to the first IDB in the section.
  // Source: draft-ietf-opsawg-pcapng-05 Section 4.4,
  // https://datatracker.ietf.org/doc/draft-ietf-opsawg-pcapng/
  const interfaceState = section.interfaces[0] || null;
  if (!interfaceState) {
    pushIssue(`Simple Packet Block at ${formatOffset(offset)} requires interface 0, but none was defined.`);
  }
  const originalLength = blockView.getUint32(8, section.littleEndian);
  const actualPacketBytes = Math.max(0, blockLength - SIMPLE_PACKET_HEADER_BYTES - BLOCK_TRAILER_BYTES);
  const capturedLength =
    interfaceState && interfaceState.snaplen > 0
      ? Math.min(interfaceState.snaplen, originalLength)
      : Math.min(originalLength, actualPacketBytes);
  if (alignUpTo(capturedLength, PCAPNG_ALIGNMENT_BYTES) > actualPacketBytes) {
    pushIssue(`Simple Packet Block at ${formatOffset(offset)} does not contain the expected packet bytes.`);
  }
  const packetSample = new Uint8Array(
    blockView.buffer,
    blockView.byteOffset + SIMPLE_PACKET_HEADER_BYTES,
    Math.min(capturedLength, Math.max(0, blockView.byteLength - SIMPLE_PACKET_HEADER_BYTES - BLOCK_TRAILER_BYTES))
  );
  updatePacketStats(
    globalTraffic,
    interfaceState,
    capturedLength,
    originalLength,
    null,
    packetSample,
    linkLayer,
    pushIssue,
    globalTraffic.totalPackets + 1
  );
};

export const parseLegacyPacketBlock = async (
  reader: FileRangeReader,
  offset: number,
  blockLength: number,
  section: SectionState,
  globalTraffic: MutableTrafficStats,
  linkLayer: PcapLinkLayerSummary | null,
  pushIssue: (message: string) => void
): Promise<void> => {
  const blockView = await reader.read(offset, blockLength);
  // The obsolete Packet Block stores Interface ID at octet 8, Drops Count at octet 10,
  // split timestamp at 12/16, and captured/original lengths at 20/24.
  // Source: draft-ietf-opsawg-pcapng-05 Appendix A Figure 20,
  // https://datatracker.ietf.org/doc/draft-ietf-opsawg-pcapng/
  if (blockView.byteLength < LEGACY_PACKET_HEADER_BYTES) {
    pushIssue(`Packet Block at ${formatOffset(offset)} is truncated.`);
    return;
  }
  const interfaceId = blockView.getUint16(8, section.littleEndian);
  const interfaceState = section.interfaces[interfaceId] || null;
  if (!interfaceState) {
    pushIssue(`Packet Block at ${formatOffset(offset)} references missing interface ${interfaceId}.`);
  }
  const capturedLength = blockView.getUint32(20, section.littleEndian);
  const originalLength = blockView.getUint32(24, section.littleEndian);
  const packetSample = new Uint8Array(
    blockView.buffer,
    blockView.byteOffset + LEGACY_PACKET_HEADER_BYTES,
    Math.min(capturedLength, Math.max(0, blockView.byteLength - LEGACY_PACKET_HEADER_BYTES - BLOCK_TRAILER_BYTES))
  );
  updatePacketStats(
    globalTraffic,
    interfaceState,
    capturedLength,
    originalLength,
    getTimestampSeconds(
      interfaceState,
      blockView.getUint32(12, section.littleEndian),
      blockView.getUint32(16, section.littleEndian),
      pushIssue,
      `Packet Block at ${formatOffset(offset)}`
    ),
    packetSample,
    linkLayer,
    pushIssue,
    globalTraffic.totalPackets + 1
  );
  const dropsCount = BigInt(blockView.getUint16(10, section.littleEndian));
  // Appendix A reserves 0xFFFF as "drop count unknown" for the obsolete Packet Block.
  // Source: draft-ietf-opsawg-pcapng-05 Appendix A,
  // https://datatracker.ietf.org/doc/draft-ietf-opsawg-pcapng/
  if (dropsCount !== 0xffffn) addObservedDropCount(interfaceState, dropsCount);
  readPacketOptions(
    blockView,
    LEGACY_PACKET_HEADER_BYTES + alignUpTo(capturedLength, PCAPNG_ALIGNMENT_BYTES),
    section.littleEndian,
    pushIssue,
    `Packet Block at ${formatOffset(offset)}`
  );
};
