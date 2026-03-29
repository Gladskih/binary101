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

export const parsePcapNg = async (
  file: File,
  pushIssue: (message: string) => void
): Promise<PcapNgParseResult | null> => {
  const reader = createFileRangeReader(file, 0, file.size);
  const firstBytes = await reader.read(0, BLOCK_HEADER_BYTES);
  if (firstBytes.byteLength < 4 || firstBytes.getUint32(0, false) !== SHB_TYPE) return null;

  const sections = [];
  const interfaceStates = [];
  const blocks = createBlockSummary();
  const nameResolution = createNameResolutionSummary();
  const globalTraffic = createMutableTrafficStats();
  let linkLayer: PcapLinkLayerSummary | null = null;
  let currentSection: SectionState | null = null;
  let truncatedFile = false;
  let offset = 0;

  // All pcapng blocks start with Block Type + Block Total Length, i.e. 8 octets.
  // Source: draft-ietf-opsawg-pcapng-05 Section 3.1,
  // https://datatracker.ietf.org/doc/draft-ietf-opsawg-pcapng/
  while (offset + BLOCK_PREFIX_BYTES <= file.size) {
    const headerView = await reader.read(offset, BLOCK_HEADER_BYTES);
    if (headerView.byteLength < BLOCK_PREFIX_BYTES) break;

    const isSectionHeader = headerView.getUint32(0, false) === SHB_TYPE;
    const littleEndian = isSectionHeader ? readSectionEndianness(headerView) : currentSection?.littleEndian ?? null;
    if (littleEndian == null) {
      truncatedFile = true;
      pushIssue(`Block at ${formatOffset(offset)} appears before a valid Section Header Block.`);
      break;
    }
    if (headerView.byteLength < BLOCK_HEADER_BYTES) {
      truncatedFile = true;
      pushIssue(`Block header at ${formatOffset(offset)} is truncated (${headerView.byteLength}/${BLOCK_HEADER_BYTES} bytes).`);
      break;
    }

    const blockType = isSectionHeader ? SHB_TYPE : headerView.getUint32(0, littleEndian);
    const blockLength = headerView.getUint32(4, littleEndian);
    const blockEnd = offset + blockLength;
    if (
      blockLength < BLOCK_HEADER_BYTES ||
      blockLength % PCAPNG_ALIGNMENT_BYTES !== 0
    ) {
      truncatedFile = true;
      pushIssue(`Block at ${formatOffset(offset)} has invalid Block Total Length ${blockLength}.`);
      break;
    }
    if (!Number.isFinite(blockEnd) || blockEnd <= offset) {
      truncatedFile = true;
      pushIssue(`Block at ${formatOffset(offset)} does not advance the file offset.`);
      break;
    }
    if (blockEnd > file.size) {
      truncatedFile = true;
      pushIssue(`Block at ${formatOffset(offset)} runs past EOF (${blockLength} bytes).`);
      break;
    }
    const trailingLength = await readBlockTailLength(reader, blockEnd, littleEndian);
    if (trailingLength != null && trailingLength !== blockLength) {
      pushIssue(`Block at ${formatOffset(offset)} has mismatched trailing Block Total Length ${trailingLength} (expected ${blockLength}).`);
    }

    blocks.totalBlocks += 1;
    if (blockType === SHB_TYPE) {
      const parsed = await parseSectionHeaderBlock(
        reader,
        offset,
        blockLength,
        sections.length,
        littleEndian,
        pushIssue
      );
      sections.push(parsed.summary);
      currentSection = parsed.state;
    } else if (blockType === IDB_TYPE) {
      blocks.interfaceDescriptionBlocks += 1;
      if (!currentSection) pushIssue(`Interface Description Block at ${formatOffset(offset)} appears outside a section.`);
      else {
        const interfaceState = await parseInterfaceDescriptionBlock(
          reader,
          offset,
          blockLength,
          currentSection,
          pushIssue
        );
        if (interfaceState) {
          currentSection.interfaces.push(interfaceState);
          interfaceStates.push(interfaceState);
        }
      }
    } else if (blockType === ENHANCED_PACKET_BLOCK_TYPE) {
      blocks.enhancedPacketBlocks += 1;
      if (!currentSection) pushIssue(`Enhanced Packet Block at ${formatOffset(offset)} appears outside a section.`);
      else {
        linkLayer = maybeEnableEthernetSummary(linkLayer, currentSection);
        await parseEnhancedPacketBlock(
          reader,
          offset,
          blockLength,
          currentSection,
          globalTraffic,
          linkLayer,
          pushIssue
        );
      }
    } else if (blockType === SIMPLE_PACKET_BLOCK_TYPE) {
      blocks.simplePacketBlocks += 1;
      if (!currentSection) pushIssue(`Simple Packet Block at ${formatOffset(offset)} appears outside a section.`);
      else {
        linkLayer = maybeEnableEthernetSummary(linkLayer, currentSection);
        await parseSimplePacketBlock(
          reader,
          offset,
          blockLength,
          currentSection,
          globalTraffic,
          linkLayer,
          pushIssue
        );
      }
    } else if (blockType === PACKET_BLOCK_TYPE) {
      blocks.packetBlocks += 1;
      if (!currentSection) pushIssue(`Packet Block at ${formatOffset(offset)} appears outside a section.`);
      else {
        linkLayer = maybeEnableEthernetSummary(linkLayer, currentSection);
        await parseLegacyPacketBlock(
          reader,
          offset,
          blockLength,
          currentSection,
          globalTraffic,
          linkLayer,
          pushIssue
        );
      }
    } else if (blockType === NAME_RESOLUTION_BLOCK_TYPE) {
      blocks.nameResolutionBlocks += 1;
      if (!currentSection) pushIssue(`Name Resolution Block at ${formatOffset(offset)} appears outside a section.`);
      else {
        await parseNameResolutionBlock(
          reader,
          offset,
          blockLength,
          currentSection,
          nameResolution,
          pushIssue
        );
      }
    } else if (blockType === INTERFACE_STATISTICS_BLOCK_TYPE) {
      blocks.interfaceStatisticsBlocks += 1;
      if (!currentSection) pushIssue(`Interface Statistics Block at ${formatOffset(offset)} appears outside a section.`);
      else {
        await parseInterfaceStatisticsBlock(reader, offset, blockLength, currentSection, pushIssue);
      }
    } else if (blockType === DECRYPTION_SECRETS_BLOCK_TYPE) {
      blocks.decryptionSecretsBlocks += 1;
    } else if (blockType === CUSTOM_BLOCK_COPYABLE_TYPE || blockType === CUSTOM_BLOCK_NOCOPY_TYPE) {
      blocks.customBlocks += 1;
    } else {
      blocks.unknownBlocks += 1;
    }

    offset = blockEnd;
  }

  if (offset < file.size) {
    truncatedFile = true;
    pushIssue(`File ends with ${file.size - offset} trailing bytes after the last complete block.`);
  }

  return {
    isPcap: true,
    format: "pcapng",
    fileSize: file.size,
    sections,
    interfaces: finalizeInterfaces(interfaceStates),
    blocks,
    nameResolution,
    packets: finalizePacketStats(globalTraffic, truncatedFile),
    linkLayer,
    issues: []
  };
};
