"use strict";

import { createFileRangeReader } from "../file-range-reader.js";
import { createEthernetSummary } from "../capture/payload-analysis.js";
import { createMutableTrafficStats, finalizePacketStats } from "../capture/stats.js";
import type { PcapLinkLayerSummary } from "../capture/types.js";
import type { PcapNgParseResult } from "./types.js";
import type { SectionState } from "./shared.js";
import {
  BLOCK_PREFIX_BYTES,
  BLOCK_HEADER_BYTES,
  CUSTOM_BLOCK_COPYABLE_TYPE,
  CUSTOM_BLOCK_NOCOPY_TYPE,
  DECRYPTION_SECRETS_BLOCK_TYPE,
  ENHANCED_PACKET_BLOCK_TYPE,
  IDB_TYPE,
  INTERFACE_STATISTICS_BLOCK_TYPE,
  NAME_RESOLUTION_BLOCK_TYPE,
  PCAPNG_ALIGNMENT_BYTES,
  PACKET_BLOCK_TYPE,
  SHB_TYPE,
  SIMPLE_PACKET_BLOCK_TYPE,
  createBlockSummary,
  createNameResolutionSummary,
  formatOffset,
  isEthernetLinkType,
  readBlockTailLength,
  readSectionEndianness
} from "./shared.js";
import { finalizeInterfaces, parseInterfaceDescriptionBlock, parseInterfaceStatisticsBlock, parseNameResolutionBlock, parseSectionHeaderBlock } from "./metadata.js";
import { parseEnhancedPacketBlock, parseLegacyPacketBlock, parseSimplePacketBlock } from "./packets.js";

const maybeEnableEthernetSummary = (
  linkLayer: PcapLinkLayerSummary | null,
  section: SectionState
): PcapLinkLayerSummary | null => {
  if (linkLayer) return linkLayer;
  return section.interfaces.some(interfaceState => isEthernetLinkType(interfaceState.linkType))
    ? { ethernet: createEthernetSummary() }
    : null;
};

type PcapNgBlockHeader = {
  blockType: number;
  blockLength: number;
  blockEnd: number;
  littleEndian: boolean;
};

type PcapNgParserState = {
  sections: PcapNgParseResult["sections"];
  interfaceStates: SectionState["interfaces"];
  blocks: PcapNgParseResult["blocks"];
  nameResolution: PcapNgParseResult["nameResolution"];
  globalTraffic: ReturnType<typeof createMutableTrafficStats>;
  linkLayer: PcapLinkLayerSummary | null;
  currentSection: SectionState | null;
  truncatedFile: boolean;
};

const createPcapNgParserState = (): PcapNgParserState => ({
  sections: [],
  interfaceStates: [],
  blocks: createBlockSummary(),
  nameResolution: createNameResolutionSummary(),
  globalTraffic: createMutableTrafficStats(),
  linkLayer: null,
  currentSection: null,
  truncatedFile: false
});

const readPcapNgBlockHeader = async (
  reader: ReturnType<typeof createFileRangeReader>,
  offset: number,
  fileSize: number,
  currentSection: SectionState | null,
  pushIssue: (message: string) => void
): Promise<PcapNgBlockHeader | null> => {
  const headerView = await reader.read(offset, BLOCK_HEADER_BYTES);
  if (headerView.byteLength < BLOCK_PREFIX_BYTES) return null;
  const isSectionHeader = headerView.getUint32(0, false) === SHB_TYPE;
  const littleEndian = isSectionHeader ? readSectionEndianness(headerView) : currentSection?.littleEndian ?? null;
  if (littleEndian == null) {
    pushIssue(`Block at ${formatOffset(offset)} appears before a valid Section Header Block.`);
    return null;
  }
  if (headerView.byteLength < BLOCK_HEADER_BYTES) {
    pushIssue(`Block header at ${formatOffset(offset)} is truncated (${headerView.byteLength}/${BLOCK_HEADER_BYTES} bytes).`);
    return null;
  }
  const blockLength = headerView.getUint32(4, littleEndian);
  const blockEnd = offset + blockLength;
  if (blockLength < BLOCK_HEADER_BYTES || blockLength % PCAPNG_ALIGNMENT_BYTES !== 0) {
    pushIssue(`Block at ${formatOffset(offset)} has invalid Block Total Length ${blockLength}.`);
    return null;
  }
  if (!Number.isFinite(blockEnd) || blockEnd <= offset) {
    pushIssue(`Block at ${formatOffset(offset)} does not advance the file offset.`);
    return null;
  }
  if (blockEnd > fileSize) {
    pushIssue(`Block at ${formatOffset(offset)} runs past EOF (${blockLength} bytes).`);
    return null;
  }
  const trailingLength = await readBlockTailLength(reader, blockEnd, littleEndian);
  if (trailingLength != null && trailingLength !== blockLength) {
    pushIssue(`Block at ${formatOffset(offset)} has mismatched trailing Block Total Length ${trailingLength} (expected ${blockLength}).`);
  }
  return {
    blockType: isSectionHeader ? SHB_TYPE : headerView.getUint32(0, littleEndian),
    blockLength,
    blockEnd,
    littleEndian
  };
};

const parsePcapNgPacketBlock = async (
  reader: ReturnType<typeof createFileRangeReader>,
  offset: number,
  blockLength: number,
  state: PcapNgParserState,
  pushIssue: (message: string) => void
): Promise<void> => {
  if (!state.currentSection) {
    pushIssue(`Packet Block at ${formatOffset(offset)} appears outside a section.`);
    return;
  }
  state.linkLayer = maybeEnableEthernetSummary(state.linkLayer, state.currentSection);
  await parseLegacyPacketBlock(
    reader,
    offset,
    blockLength,
    state.currentSection,
    state.globalTraffic,
    state.linkLayer,
    pushIssue
  );
};

const dispatchPcapNgBlock = async (
  reader: ReturnType<typeof createFileRangeReader>,
  offset: number,
  header: PcapNgBlockHeader,
  state: PcapNgParserState,
  pushIssue: (message: string) => void
): Promise<void> => {
  state.blocks.totalBlocks += 1;
  if (header.blockType === SHB_TYPE) {
    const parsed = await parseSectionHeaderBlock(
      reader,
      offset,
      header.blockLength,
      state.sections.length,
      header.littleEndian,
      pushIssue
    );
    state.sections.push(parsed.summary);
    state.currentSection = parsed.state;
  } else if (header.blockType === IDB_TYPE) {
    state.blocks.interfaceDescriptionBlocks += 1;
    if (!state.currentSection) pushIssue(`Interface Description Block at ${formatOffset(offset)} appears outside a section.`);
    else {
      const interfaceState = await parseInterfaceDescriptionBlock(
        reader,
        offset,
        header.blockLength,
        state.currentSection,
        pushIssue
      );
      if (interfaceState) {
        state.currentSection.interfaces.push(interfaceState);
        state.interfaceStates.push(interfaceState);
      }
    }
  } else {
    await dispatchPcapNgDataBlock(reader, offset, header, state, pushIssue);
  }
};

const dispatchPcapNgDataBlock = async (
  reader: ReturnType<typeof createFileRangeReader>,
  offset: number,
  header: PcapNgBlockHeader,
  state: PcapNgParserState,
  pushIssue: (message: string) => void
): Promise<void> => {
  if (header.blockType === ENHANCED_PACKET_BLOCK_TYPE || header.blockType === SIMPLE_PACKET_BLOCK_TYPE) {
    await dispatchPcapNgModernPacketBlock(reader, offset, header, state, pushIssue);
  } else if (header.blockType === PACKET_BLOCK_TYPE) {
    state.blocks.packetBlocks += 1;
    await parsePcapNgPacketBlock(reader, offset, header.blockLength, state, pushIssue);
  } else if (header.blockType === NAME_RESOLUTION_BLOCK_TYPE) {
    state.blocks.nameResolutionBlocks += 1;
    if (!state.currentSection) pushIssue(`Name Resolution Block at ${formatOffset(offset)} appears outside a section.`);
    else {
      await parseNameResolutionBlock(
        reader,
        offset,
        header.blockLength,
        state.currentSection,
        state.nameResolution,
        pushIssue
      );
    }
  } else if (header.blockType === INTERFACE_STATISTICS_BLOCK_TYPE) {
    state.blocks.interfaceStatisticsBlocks += 1;
    if (!state.currentSection) pushIssue(`Interface Statistics Block at ${formatOffset(offset)} appears outside a section.`);
    else await parseInterfaceStatisticsBlock(reader, offset, header.blockLength, state.currentSection, pushIssue);
  } else if (header.blockType === DECRYPTION_SECRETS_BLOCK_TYPE) state.blocks.decryptionSecretsBlocks += 1;
  else if (header.blockType === CUSTOM_BLOCK_COPYABLE_TYPE || header.blockType === CUSTOM_BLOCK_NOCOPY_TYPE) {
    state.blocks.customBlocks += 1;
  }
  else state.blocks.unknownBlocks += 1;
};

const dispatchPcapNgModernPacketBlock = async (
  reader: ReturnType<typeof createFileRangeReader>,
  offset: number,
  header: PcapNgBlockHeader,
  state: PcapNgParserState,
  pushIssue: (message: string) => void
): Promise<void> => {
  const isEnhanced = header.blockType === ENHANCED_PACKET_BLOCK_TYPE;
  if (isEnhanced) state.blocks.enhancedPacketBlocks += 1;
  else state.blocks.simplePacketBlocks += 1;
  if (!state.currentSection) {
    pushIssue(
      `${isEnhanced ? "Enhanced Packet" : "Simple Packet"} Block at ${formatOffset(offset)} appears outside a section.`
    );
    return;
  }
  state.linkLayer = maybeEnableEthernetSummary(state.linkLayer, state.currentSection);
  if (isEnhanced) {
    await parseEnhancedPacketBlock(
      reader,
      offset,
      header.blockLength,
      state.currentSection,
      state.globalTraffic,
      state.linkLayer,
      pushIssue
    );
  } else {
    await parseSimplePacketBlock(
      reader,
      offset,
      header.blockLength,
      state.currentSection,
      state.globalTraffic,
      state.linkLayer,
      pushIssue
    );
  }
};

export const parsePcapNg = async (
  file: File,
  pushIssue: (message: string) => void
): Promise<PcapNgParseResult | null> => {
  const reader = createFileRangeReader(file, 0, file.size);
  const firstBytes = await reader.read(0, BLOCK_HEADER_BYTES);
  if (firstBytes.byteLength < 4 || firstBytes.getUint32(0, false) !== SHB_TYPE) return null;
  const state = createPcapNgParserState();
  let offset = 0;
  while (offset + BLOCK_PREFIX_BYTES <= file.size) {
    const header = await readPcapNgBlockHeader(reader, offset, file.size, state.currentSection, pushIssue);
    if (!header) {
      state.truncatedFile = true;
      break;
    }
    await dispatchPcapNgBlock(reader, offset, header, state, pushIssue);
    offset = header.blockEnd;
  }

  if (offset < file.size) {
    state.truncatedFile = true;
    pushIssue(`File ends with ${file.size - offset} trailing bytes after the last complete block.`);
  }

  return {
    isPcap: true,
    format: "pcapng",
    fileSize: file.size,
    sections: state.sections,
    interfaces: finalizeInterfaces(state.interfaceStates),
    blocks: state.blocks,
    nameResolution: state.nameResolution,
    packets: finalizePacketStats(state.globalTraffic, state.truncatedFile),
    linkLayer: state.linkLayer,
    issues: []
  };
};
