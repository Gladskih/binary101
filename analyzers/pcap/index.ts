"use strict";

import { createFileRangeReader } from "../file-range-reader.js";
import { LINKTYPE_ETHERNET, describeLinkType } from "../capture/link-types.js";
import { analyzeEthernetSample, createEthernetSummary } from "../capture/payload-analysis.js";
import { createMutableTrafficStats, finalizePacketStats, observePacket } from "../capture/stats.js";
import type { PcapLinkLayerSummary } from "../capture/types.js";
import type { PcapClassicParseResult, PcapGlobalHeader, PcapTimestampResolution } from "./types.js";

// The classic pcap File Header is 24 octets and each Packet Record header is 16 octets.
// Source: draft-ietf-opsawg-pcap-07 Section 4 Figure 1 and Section 5 Figure 3,
// https://datatracker.ietf.org/doc/html/draft-ietf-opsawg-pcap
const GLOBAL_HEADER_SIZE = 24;
const RECORD_HEADER_SIZE = 16;

// Classic pcap defines two canonical magic numbers, each written in native-endian byte order:
// 0xA1B2C3D4 means microsecond timestamps, 0xA1B23C4D means nanosecond timestamps.
// Source: draft-ietf-opsawg-pcap-07 Section 4.1,
// https://datatracker.ietf.org/doc/html/draft-ietf-opsawg-pcap
const PCAP_MAGIC_USEC = 0xa1b2c3d4;
const PCAP_MAGIC_NSEC = 0xa1b23c4d;
const PCAP_MAGIC_USEC_SWAPPED = 0xd4c3b2a1;
const PCAP_MAGIC_NSEC_SWAPPED = 0x4d3cb2a1;

const detectClassicPcapMagic = (
  dv: DataView
): { littleEndian: boolean; timestampResolution: PcapTimestampResolution } | null => {
  if (dv.byteLength < 4) return null;

  const magic = dv.getUint32(0, false);
  if (magic === PCAP_MAGIC_USEC) {
    return { littleEndian: false, timestampResolution: "microseconds" };
  }
  if (magic === PCAP_MAGIC_NSEC) {
    return { littleEndian: false, timestampResolution: "nanoseconds" };
  }
  if (magic === PCAP_MAGIC_USEC_SWAPPED) {
    return { littleEndian: true, timestampResolution: "microseconds" };
  }
  if (magic === PCAP_MAGIC_NSEC_SWAPPED) {
    return { littleEndian: true, timestampResolution: "nanoseconds" };
  }
  return null;
};

const createGlobalHeader = (
  littleEndian: boolean,
  timestampResolution: PcapTimestampResolution
): PcapGlobalHeader => ({
  littleEndian,
  timestampResolution,
  versionMajor: null,
  versionMinor: null,
  thiszone: null,
  sigfigs: null,
  snaplen: null,
  network: null,
  networkName: null
});

const createLinkLayerSummary = (linkType: number | null): PcapLinkLayerSummary | null =>
  linkType === LINKTYPE_ETHERNET ? { ethernet: createEthernetSummary() } : null;

export const parsePcap = async (file: File): Promise<PcapClassicParseResult | null> => {
  const issues: string[] = [];
  const pushIssue = (message: string): void => {
    issues.push(message);
  };

  const reader = createFileRangeReader(file, 0, file.size);
  const headerDv = await reader.read(0, GLOBAL_HEADER_SIZE);
  const magic = detectClassicPcapMagic(headerDv);
  if (!magic) return null;

  const header = createGlobalHeader(magic.littleEndian, magic.timestampResolution);
  const traffic = createMutableTrafficStats();
  let truncatedFile = false;

  if (headerDv.byteLength < GLOBAL_HEADER_SIZE) {
    truncatedFile = true;
    pushIssue(`Global header is truncated (${headerDv.byteLength}/${GLOBAL_HEADER_SIZE} bytes).`);
    return {
      isPcap: true,
      format: "pcap",
      fileSize: file.size,
      header,
      packets: finalizePacketStats(traffic, truncatedFile),
      linkLayer: null,
      issues
    };
  }

  const littleEndian = magic.littleEndian;
  // File Header field offsets come directly from Figure 1:
  // version_major/version_minor/reserved1/reserved2/snaplen/linktype are at 4/6/8/12/16/20.
  header.versionMajor = headerDv.getUint16(4, littleEndian);
  header.versionMinor = headerDv.getUint16(6, littleEndian);
  header.thiszone = headerDv.getInt32(8, littleEndian);
  header.sigfigs = headerDv.getUint32(12, littleEndian);
  header.snaplen = headerDv.getUint32(16, littleEndian);
  header.network = headerDv.getUint32(20, littleEndian);
  header.networkName =
    header.network != null ? describeLinkType(header.network) || `LinkType ${header.network}` : null;

  // The historical pcap format documented by the IETF is version 2.4.
  // Source: draft-ietf-opsawg-pcap-07 Section 4,
  // https://datatracker.ietf.org/doc/html/draft-ietf-opsawg-pcap
  if (header.versionMajor !== 2 || header.versionMinor !== 4) {
    pushIssue(`Unusual PCAP version ${header.versionMajor}.${header.versionMinor} (expected 2.4).`);
  }

  const linkLayer = createLinkLayerSummary(header.network);
  const ethernet = linkLayer?.ethernet || null;
  // These are SI unit conversions used to normalize the sub-second timestamp field into seconds.
  // The pcap magic number decides whether the packet field is in microseconds or nanoseconds.
  const subSecondDivisor =
    magic.timestampResolution === "microseconds" ? 1_000_000 : 1_000_000_000;

  let offset = GLOBAL_HEADER_SIZE;
  while (offset + RECORD_HEADER_SIZE <= file.size) {
    const recordDv = await reader.read(offset, RECORD_HEADER_SIZE);
    if (recordDv.byteLength < RECORD_HEADER_SIZE) break;

    const packetIndex = traffic.totalPackets + 1;
    // Packet Record field offsets come directly from Figure 3:
    // ts_sec/ts_subsec/captured_len/original_len are at 0/4/8/12.
    const capturedLength = recordDv.getUint32(8, littleEndian);
    const originalLength = recordDv.getUint32(12, littleEndian);

    if (originalLength < capturedLength) {
      pushIssue(
        `Packet #${packetIndex} has captured length (${capturedLength}) larger than original length (${originalLength}).`
      );
    }
    if (header.snaplen != null && capturedLength > header.snaplen) {
      pushIssue(
        `Packet #${packetIndex} captured length (${capturedLength}) exceeds snaplen (${header.snaplen}).`
      );
    }

    const recordEnd = offset + RECORD_HEADER_SIZE + capturedLength;
    if (!Number.isFinite(recordEnd) || recordEnd < offset) {
      truncatedFile = true;
      pushIssue(`Packet #${packetIndex} has an invalid captured length (${capturedLength}).`);
      break;
    }

    const timestampSeconds =
      recordDv.getUint32(0, littleEndian) + recordDv.getUint32(4, littleEndian) / subSecondDivisor;
    observePacket(traffic, capturedLength, originalLength, timestampSeconds);

    const recordView = await reader.read(offset, RECORD_HEADER_SIZE + capturedLength);
    const payloadAvailable = Math.max(0, recordView.byteLength - RECORD_HEADER_SIZE);
    if (payloadAvailable > 0) {
      analyzeEthernetSample(
        new Uint8Array(
          recordView.buffer,
          recordView.byteOffset + RECORD_HEADER_SIZE,
          Math.min(capturedLength, payloadAvailable)
        ),
        ethernet
      );
    }

    if (recordEnd > file.size) {
      truncatedFile = true;
      pushIssue(
        `Packet #${traffic.totalPackets} payload runs past EOF (need ${capturedLength} bytes at offset ${offset + RECORD_HEADER_SIZE}).`
      );
      break;
    }

    offset = recordEnd;
  }

  if (offset < file.size && offset + RECORD_HEADER_SIZE > file.size) {
    truncatedFile = true;
    pushIssue(`File ends with ${file.size - offset} trailing bytes (truncated packet record header).`);
  }

  return {
    isPcap: true,
    format: "pcap",
    fileSize: file.size,
    header,
    packets: finalizePacketStats(traffic, truncatedFile),
    linkLayer,
    issues
  };
};
