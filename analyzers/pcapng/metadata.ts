"use strict";

import type { FileRangeReader } from "../file-range-reader.js";
import { alignUpTo } from "../../binary-utils.js";
import { describeLinkType } from "../capture/link-types.js";
import { createMutableTrafficStats, finalizeTrafficStats } from "../capture/stats.js";
import { decodeUtf8, describeTimestampResolution, parsePcapNgOptions, readFilterOption, readInt64Option } from "./options.js";
import type {
  PcapNgInterfaceStatistics,
  PcapNgInterfaceSummary,
  PcapNgNameResolutionSummary,
  PcapNgSectionSummary
} from "./types.js";
import type { InterfaceState, SectionState } from "./shared.js";
import {
  BLOCK_TRAILER_BYTES,
  NRB_RECORD_END,
  NRB_RECORD_IPV4,
  NRB_RECORD_IPV6,
  PCAPNG_ALIGNMENT_BYTES,
  findOption,
  formatOffset,
  joinUint64,
  readBigInt64,
  readMetadataBlock,
  readUint64OptionValue
} from "./shared.js";

const createSectionSummary = (
  index: number,
  littleEndian: boolean,
  blockView: DataView,
  pushIssue: (message: string) => void,
  offset: number
): PcapNgSectionSummary => {
  // SHB field offsets come from Figure 9:
  // Major/Minor Version are at octets 12/14 and Section Length begins at octet 16.
  // Source: draft-ietf-opsawg-pcapng-05 Section 4.1 Figure 9,
  // https://datatracker.ietf.org/doc/draft-ietf-opsawg-pcapng/
  const versionMajor = blockView.byteLength >= 14 ? blockView.getUint16(12, littleEndian) : null;
  const versionMinor = blockView.byteLength >= 16 ? blockView.getUint16(14, littleEndian) : null;
  const sectionLength = blockView.byteLength >= 24 ? readBigInt64(blockView, 16, littleEndian) : null;
  // The current writer version is 1.0, but readers must treat legacy 1.2 files as equivalent.
  // Source: draft-ietf-opsawg-pcapng-05 Section 4.1,
  // https://datatracker.ietf.org/doc/draft-ietf-opsawg-pcapng/
  if (versionMajor !== 1 || (versionMinor !== 0 && versionMinor !== 2)) {
    pushIssue(`Section #${index} at ${formatOffset(offset)} uses pcapng version ${versionMajor}.${versionMinor}.`);
  }
  if (sectionLength != null && sectionLength < -1n) {
    pushIssue(`Section #${index} at ${formatOffset(offset)} has invalid Section Length ${sectionLength}.`);
  }
  let hardware: string | null = null;
  let os: string | null = null;
  let userAppl: string | null = null;
  if (blockView.byteLength >= 28) {
    const options = parsePcapNgOptions(
      blockView,
      24,
      blockView.byteLength - BLOCK_TRAILER_BYTES,
      littleEndian,
      pushIssue,
      `Section #${index}`
    );
    for (const option of options) {
      // SHB option codes: shb_hardware=2, shb_os=3, shb_userappl=4.
      // Source: draft-ietf-opsawg-pcapng-05 Section 4.1 Table 2,
      // https://datatracker.ietf.org/doc/draft-ietf-opsawg-pcapng/
      if (option.code === 2) hardware = decodeUtf8(option.value);
      if (option.code === 3) os = decodeUtf8(option.value);
      if (option.code === 4) userAppl = decodeUtf8(option.value);
    }
  }
  return {
    index,
    littleEndian,
    versionMajor,
    versionMinor,
    sectionLength: sectionLength != null && sectionLength >= 0n ? sectionLength : null,
    hardware,
    os,
    userAppl
  };
};

export const parseSectionHeaderBlock = async (
  reader: FileRangeReader,
  offset: number,
  blockLength: number,
  sectionIndex: number,
  littleEndian: boolean,
  pushIssue: (message: string) => void
): Promise<{ summary: PcapNgSectionSummary; state: SectionState }> => {
  const blockView = await readMetadataBlock(reader, offset, blockLength);
  return {
    summary: createSectionSummary(sectionIndex, littleEndian, blockView, pushIssue, offset),
    state: { index: sectionIndex, littleEndian, interfaces: [] }
  };
};

export const parseInterfaceDescriptionBlock = async (
  reader: FileRangeReader,
  offset: number,
  blockLength: number,
  section: SectionState,
  pushIssue: (message: string) => void
): Promise<InterfaceState | null> => {
  const blockView = await readMetadataBlock(reader, offset, blockLength);
  // Figure 10 gives IDB a 16-octet fixed header; LinkType and SnapLen live at octets 8 and 12.
  // Source: draft-ietf-opsawg-pcapng-05 Section 4.2 Figure 10,
  // https://datatracker.ietf.org/doc/draft-ietf-opsawg-pcapng/
  if (blockView.byteLength < 16) {
    pushIssue(`Interface Description Block for section #${section.index} is truncated.`);
    return null;
  }
  const linkType = blockView.getUint16(8, section.littleEndian);
  const snaplen = blockView.getUint32(12, section.littleEndian);
  let name: string | null = null;
  let description: string | null = null;
  let hardware: string | null = null;
  let os: string | null = null;
  let filter: string | null = null;
  let timestampOffsetSeconds: bigint | null = 0n;
  const interfaceId = section.interfaces.length;
  const options = parsePcapNgOptions(
    blockView,
    16,
    blockView.byteLength - BLOCK_TRAILER_BYTES,
    section.littleEndian,
    pushIssue,
    `Interface #${interfaceId} in section #${section.index}`
  );
  // IDB option codes used here:
  // if_name=2, if_description=3, if_tsresol=9, if_filter=11, if_os=12,
  // if_tsoffset=14, if_hardware=15.
  // Source: draft-ietf-opsawg-pcapng-05 Section 4.2 Table 3,
  // https://datatracker.ietf.org/doc/draft-ietf-opsawg-pcapng/
  const resolution = describeTimestampResolution(findOption(options, 9)?.value || null);
  for (const option of options) {
    if (option.code === 2) name = decodeUtf8(option.value);
    if (option.code === 3) description = decodeUtf8(option.value);
    if (option.code === 11) filter = readFilterOption(option);
    if (option.code === 12) os = decodeUtf8(option.value);
    if (option.code === 14) {
      timestampOffsetSeconds = readInt64Option(option, section.littleEndian);
      if (timestampOffsetSeconds == null) {
        pushIssue(`Interface #${interfaceId} in section #${section.index} has an unsupported if_tsoffset value.`);
      }
    }
    if (option.code === 15) hardware = decodeUtf8(option.value);
  }
  return {
    sectionIndex: section.index,
    interfaceId,
    linkType,
    linkTypeName: describeLinkType(linkType) || `LinkType ${linkType}`,
    snaplen,
    name,
    description,
    hardware,
    os,
    filter,
    timestampResolution: resolution.label,
    unitsPerSecond: resolution.unitsPerSecond,
    timestampOffsetSeconds,
    observedDropCount: null,
    statistics: null,
    traffic: createMutableTrafficStats()
  };
};

export const parseNameResolutionBlock = async (
  reader: FileRangeReader,
  offset: number,
  blockLength: number,
  section: SectionState,
  nameResolution: PcapNgNameResolutionSummary,
  pushIssue: (message: string) => void
): Promise<void> => {
  const blockView = await readMetadataBlock(reader, offset, blockLength);
  // Figure 14 starts the NRB records immediately after the 8-octet block prefix.
  // Source: draft-ietf-opsawg-pcapng-05 Section 4.5 Figure 14,
  // https://datatracker.ietf.org/doc/draft-ietf-opsawg-pcapng/
  let cursor = 8;
  const end = blockView.byteLength - BLOCK_TRAILER_BYTES;
  let sawEndMarker = false;
  while (cursor + 4 <= end) {
    const recordType = blockView.getUint16(cursor, section.littleEndian);
    const recordLength = blockView.getUint16(cursor + 2, section.littleEndian);
    cursor += 4;
    if (recordType === NRB_RECORD_END) {
      sawEndMarker = true;
      break;
    }
    const recordEnd = cursor + recordLength;
    if (recordEnd > end) {
      pushIssue(`Name Resolution Block at ${formatOffset(offset)} has a record that runs past the block.`);
      return;
    }
    if (recordType === NRB_RECORD_IPV4) nameResolution.ipv4Records += 1;
    else if (recordType === NRB_RECORD_IPV6) nameResolution.ipv6Records += 1;
    else nameResolution.otherRecords += 1;
    cursor += alignUpTo(recordLength, PCAPNG_ALIGNMENT_BYTES);
  }
  if (!sawEndMarker) {
    nameResolution.missingEndMarkers += 1;
    pushIssue(`Name Resolution Block at ${formatOffset(offset)} is missing nrb_record_end.`);
    return;
  }
  parsePcapNgOptions(
    blockView,
    cursor,
    end,
    section.littleEndian,
    pushIssue,
    `Name Resolution Block at ${formatOffset(offset)}`
  );
};

const buildInterfaceStatistics = (
  blockView: DataView,
  littleEndian: boolean,
  offset: number,
  pushIssue: (message: string) => void
): PcapNgInterfaceStatistics => {
  // Figure 16 gives ISB a 20-octet fixed header; Interface ID starts at octet 8 and the
  // split 64-bit timestamp occupies octets 12 and 16.
  // Source: draft-ietf-opsawg-pcapng-05 Section 4.6 Figure 16,
  // https://datatracker.ietf.org/doc/draft-ietf-opsawg-pcapng/
  const options = parsePcapNgOptions(
    blockView,
    20,
    blockView.byteLength - BLOCK_TRAILER_BYTES,
    littleEndian,
    pushIssue,
    `Interface Statistics Block at ${formatOffset(offset)}`
  );
  const readCounter = (code: number): bigint | null =>
    readUint64OptionValue(options, code, littleEndian, pushIssue, `Interface Statistics Block at ${formatOffset(offset)}`);
  return {
    timestamp: joinUint64(
      blockView.getUint32(12, littleEndian),
      blockView.getUint32(16, littleEndian)
    ),
    // ISB option codes:
    // isb_starttime=2, isb_endtime=3, isb_ifrecv=4, isb_ifdrop=5,
    // isb_filteraccept=6, isb_osdrop=7, isb_usrdeliv=8.
    // Source: draft-ietf-opsawg-pcapng-05 Section 4.6 Table 8,
    // https://datatracker.ietf.org/doc/draft-ietf-opsawg-pcapng/
    captureStart: readCounter(2),
    captureEnd: readCounter(3),
    receivedPackets: readCounter(4),
    droppedByInterface: readCounter(5),
    acceptedByFilter: readCounter(6),
    droppedByOs: readCounter(7),
    deliveredToUser: readCounter(8)
  };
};

export const parseInterfaceStatisticsBlock = async (
  reader: FileRangeReader,
  offset: number,
  blockLength: number,
  section: SectionState,
  pushIssue: (message: string) => void
): Promise<void> => {
  const blockView = await readMetadataBlock(reader, offset, blockLength);
  // Figure 16 gives ISB a 20-octet fixed header.
  // Source: draft-ietf-opsawg-pcapng-05 Section 4.6 Figure 16,
  // https://datatracker.ietf.org/doc/draft-ietf-opsawg-pcapng/
  if (blockView.byteLength < 20) {
    pushIssue(`Interface Statistics Block at ${formatOffset(offset)} is truncated.`);
    return;
  }
  const interfaceId = blockView.getUint32(8, section.littleEndian);
  const interfaceState = section.interfaces[interfaceId] || null;
  if (!interfaceState) {
    pushIssue(`Interface Statistics Block at ${formatOffset(offset)} references missing interface ${interfaceId}.`);
    return;
  }
  interfaceState.statistics = buildInterfaceStatistics(
    blockView,
    section.littleEndian,
    offset,
    pushIssue
  );
};

export const finalizeInterfaces = (interfaces: InterfaceState[]): PcapNgInterfaceSummary[] =>
  interfaces.map(interfaceState => ({
    sectionIndex: interfaceState.sectionIndex,
    interfaceId: interfaceState.interfaceId,
    linkType: interfaceState.linkType,
    linkTypeName: interfaceState.linkTypeName,
    snaplen: interfaceState.snaplen,
    name: interfaceState.name,
    description: interfaceState.description,
    hardware: interfaceState.hardware,
    os: interfaceState.os,
    filter: interfaceState.filter,
    timestampResolution: interfaceState.timestampResolution,
    timestampOffsetSeconds: interfaceState.timestampOffsetSeconds,
    observedDropCount: interfaceState.observedDropCount,
    statistics: interfaceState.statistics,
    packets: finalizeTrafficStats(interfaceState.traffic)
  }));
