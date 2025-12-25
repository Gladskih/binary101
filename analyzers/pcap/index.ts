"use strict";

import type {
  PcapEthernetSummary,
  PcapGlobalHeader,
  PcapPacketStats,
  PcapParseResult,
  PcapTimestampResolution
} from "./types.js";

const GLOBAL_HEADER_SIZE = 24;
const RECORD_HEADER_SIZE = 16;
const MAX_ISSUES = 200;
const PAYLOAD_SAMPLE_BYTES = 128;

const PCAP_MAGIC_USEC = 0xa1b2c3d4;
const PCAP_MAGIC_NSEC = 0xa1b23c4d;
const PCAP_MAGIC_USEC_SWAPPED = 0xd4c3b2a1;
const PCAP_MAGIC_NSEC_SWAPPED = 0x4d3cb2a1;

const describeLinkType = (linkType: number): string | null => {
  if (linkType === 0) return "Null/loopback";
  if (linkType === 1) return "Ethernet";
  if (linkType === 101) return "Raw IP";
  if (linkType === 105) return "IEEE 802.11";
  if (linkType === 113) return "Linux cooked capture";
  return null;
};

const detectPcapMagic = (
  dv: DataView
): { littleEndian: boolean; timestampResolution: PcapTimestampResolution } | null => {
  if (dv.byteLength < 4) return null;
  const magic = dv.getUint32(0, false);
  if (magic === PCAP_MAGIC_USEC) return { littleEndian: false, timestampResolution: "microseconds" };
  if (magic === PCAP_MAGIC_NSEC) return { littleEndian: false, timestampResolution: "nanoseconds" };
  if (magic === PCAP_MAGIC_USEC_SWAPPED) return { littleEndian: true, timestampResolution: "microseconds" };
  if (magic === PCAP_MAGIC_NSEC_SWAPPED) return { littleEndian: true, timestampResolution: "nanoseconds" };
  return null;
};

const incrementMapCount = (map: Map<number, number>, key: number): void => {
  map.set(key, (map.get(key) || 0) + 1);
};

const readUint16be = (bytes: Uint8Array, offset: number): number | null => {
  if (offset + 2 > bytes.length) return null;
  return ((bytes[offset] ?? 0) << 8) | (bytes[offset + 1] ?? 0);
};

const parseEthernetFromSample = (
  sample: Uint8Array,
  ethernet: PcapEthernetSummary
): { etherType: number | null; etherPayloadOffset: number | null } => {
  if (sample.length < 14) {
    ethernet.shortFrames += 1;
    return { etherType: null, etherPayloadOffset: null };
  }

  let etherType = readUint16be(sample, 12);
  if (etherType == null) {
    ethernet.shortFrames += 1;
    return { etherType: null, etherPayloadOffset: null };
  }

  let payloadOffset = 14;
  if (etherType === 0x8100 || etherType === 0x88a8) {
    if (sample.length < 18) {
      ethernet.shortFrames += 1;
      return { etherType: null, etherPayloadOffset: null };
    }
    ethernet.vlanTaggedFrames += 1;
    const inner = readUint16be(sample, 16);
    if (inner == null) {
      ethernet.shortFrames += 1;
      return { etherType: null, etherPayloadOffset: null };
    }
    etherType = inner;
    payloadOffset = 18;
  }

  incrementMapCount(ethernet.etherTypes, etherType);
  ethernet.framesParsed += 1;
  return { etherType, etherPayloadOffset: payloadOffset };
};

const parseIpProtocolFromEthernetSample = (
  sample: Uint8Array,
  etherType: number,
  etherPayloadOffset: number,
  ethernet: PcapEthernetSummary
): void => {
  if (etherType === 0x0800) {
    if (etherPayloadOffset + 10 > sample.length) return;
    const verIhl = sample[etherPayloadOffset] ?? 0;
    const version = verIhl >>> 4;
    if (version !== 4) return;
    const protocol = sample[etherPayloadOffset + 9] ?? 0;
    incrementMapCount(ethernet.ipProtocols, protocol);
    return;
  }

  if (etherType === 0x86dd) {
    if (etherPayloadOffset + 7 > sample.length) return;
    const version = (sample[etherPayloadOffset] ?? 0) >>> 4;
    if (version !== 6) return;
    const nextHeader = sample[etherPayloadOffset + 6] ?? 0;
    incrementMapCount(ethernet.ipProtocols, nextHeader);
  }
};

export const parsePcap = async (file: File): Promise<PcapParseResult | null> => {
  const issues: string[] = [];
  const pushIssue = (message: string): void => {
    if (issues.length >= MAX_ISSUES) return;
    issues.push(message);
  };

  const headerSlice = await file.slice(0, Math.min(file.size, GLOBAL_HEADER_SIZE)).arrayBuffer();
  const headerDv = new DataView(headerSlice);
  const magic = detectPcapMagic(headerDv);
  if (!magic) return null;

  const header: PcapGlobalHeader = {
    littleEndian: magic.littleEndian,
    timestampResolution: magic.timestampResolution,
    versionMajor: null,
    versionMinor: null,
    thiszone: null,
    sigfigs: null,
    snaplen: null,
    network: null,
    networkName: null
  };

  const packets: PcapPacketStats = {
    totalPackets: 0,
    totalCapturedBytes: 0,
    totalOriginalBytes: 0,
    capturedLengthMin: null,
    capturedLengthMax: null,
    capturedLengthAverage: null,
    originalLengthMin: null,
    originalLengthMax: null,
    originalLengthAverage: null,
    truncatedPackets: 0,
    truncatedFile: false,
    timestampMinSeconds: null,
    timestampMaxSeconds: null,
    outOfOrderTimestamps: 0
  };

  if (headerSlice.byteLength < GLOBAL_HEADER_SIZE) {
    pushIssue(`Global header is truncated (${headerSlice.byteLength}/${GLOBAL_HEADER_SIZE} bytes).`);
    packets.truncatedFile = true;
    return { isPcap: true, fileSize: file.size, header, packets, linkLayer: null, issues };
  }

  const le = magic.littleEndian;
  header.versionMajor = headerDv.getUint16(4, le);
  header.versionMinor = headerDv.getUint16(6, le);
  header.thiszone = headerDv.getInt32(8, le);
  header.sigfigs = headerDv.getUint32(12, le);
  header.snaplen = headerDv.getUint32(16, le);
  header.network = headerDv.getUint32(20, le);
  header.networkName =
    header.network != null ? describeLinkType(header.network) || `LinkType ${header.network}` : null;

  if (header.versionMajor !== 2 || header.versionMinor !== 4) {
    pushIssue(`Unusual PCAP version ${header.versionMajor}.${header.versionMinor} (expected 2.4).`);
  }

  let ethernet: PcapEthernetSummary | null = null;
  if (header.network === 1) {
    ethernet = {
      framesParsed: 0,
      vlanTaggedFrames: 0,
      shortFrames: 0,
      etherTypes: new Map<number, number>(),
      ipProtocols: new Map<number, number>()
    };
  }
  const linkLayer = ethernet ? { ethernet } : null;

  const subSecondDivisor = magic.timestampResolution === "microseconds" ? 1_000_000 : 1_000_000_000;
  let lastTimestamp: number | null = null;

  let offset = GLOBAL_HEADER_SIZE;
  while (offset + RECORD_HEADER_SIZE <= file.size) {
    const recordSliceEnd = Math.min(file.size, offset + RECORD_HEADER_SIZE + PAYLOAD_SAMPLE_BYTES);
    const recordChunk = new Uint8Array(await file.slice(offset, recordSliceEnd).arrayBuffer());
    if (recordChunk.length < RECORD_HEADER_SIZE) break;

    const recordDv = new DataView(recordChunk.buffer, recordChunk.byteOffset, recordChunk.byteLength);
    const tsSeconds = recordDv.getUint32(0, le);
    const tsSubseconds = recordDv.getUint32(4, le);
    const capturedLength = recordDv.getUint32(8, le);
    const originalLength = recordDv.getUint32(12, le);

    packets.totalPackets += 1;
    packets.totalCapturedBytes += capturedLength;
    packets.totalOriginalBytes += originalLength;

    if (packets.capturedLengthMin == null || capturedLength < packets.capturedLengthMin) {
      packets.capturedLengthMin = capturedLength;
    }
    if (packets.capturedLengthMax == null || capturedLength > packets.capturedLengthMax) {
      packets.capturedLengthMax = capturedLength;
    }
    if (packets.originalLengthMin == null || originalLength < packets.originalLengthMin) {
      packets.originalLengthMin = originalLength;
    }
    if (packets.originalLengthMax == null || originalLength > packets.originalLengthMax) {
      packets.originalLengthMax = originalLength;
    }

    if (originalLength > capturedLength) packets.truncatedPackets += 1;
    if (originalLength < capturedLength) {
      pushIssue(
        `Packet #${packets.totalPackets} has captured length (${capturedLength}) larger than original length (${originalLength}).`
      );
    }

    if (header.snaplen != null && capturedLength > header.snaplen) {
      pushIssue(
        `Packet #${packets.totalPackets} captured length (${capturedLength}) exceeds snaplen (${header.snaplen}).`
      );
    }

    const timestampSeconds = tsSeconds + tsSubseconds / subSecondDivisor;
    if (packets.timestampMinSeconds == null || timestampSeconds < packets.timestampMinSeconds) {
      packets.timestampMinSeconds = timestampSeconds;
    }
    if (packets.timestampMaxSeconds == null || timestampSeconds > packets.timestampMaxSeconds) {
      packets.timestampMaxSeconds = timestampSeconds;
    }
    if (lastTimestamp != null && timestampSeconds < lastTimestamp) {
      packets.outOfOrderTimestamps += 1;
    }
    lastTimestamp = timestampSeconds;

    const recordEnd = offset + RECORD_HEADER_SIZE + capturedLength;
    if (!Number.isFinite(recordEnd) || recordEnd < offset) {
      packets.truncatedFile = true;
      pushIssue(`Packet #${packets.totalPackets} has an invalid captured length (${capturedLength}).`);
      break;
    }

    const payloadAvailable = Math.max(0, recordChunk.length - RECORD_HEADER_SIZE);
    const sampleLength = Math.min(capturedLength, payloadAvailable);
    if (ethernet && sampleLength > 0) {
      const payloadSample = recordChunk.subarray(RECORD_HEADER_SIZE, RECORD_HEADER_SIZE + sampleLength);
      const { etherType, etherPayloadOffset } = parseEthernetFromSample(payloadSample, ethernet);
      if (etherType != null && etherPayloadOffset != null) {
        parseIpProtocolFromEthernetSample(payloadSample, etherType, etherPayloadOffset, ethernet);
      }
    }

    if (recordEnd > file.size) {
      packets.truncatedFile = true;
      pushIssue(
        `Packet #${packets.totalPackets} payload runs past EOF (need ${capturedLength} bytes at offset ${offset + RECORD_HEADER_SIZE}).`
      );
      break;
    }

    offset = recordEnd;
  }

  if (offset < file.size && offset + RECORD_HEADER_SIZE > file.size) {
    packets.truncatedFile = true;
    pushIssue(
      `File ends with ${file.size - offset} trailing bytes (truncated packet record header).`
    );
  }

  if (packets.totalPackets > 0) {
    packets.capturedLengthAverage = Math.round((packets.totalCapturedBytes / packets.totalPackets) * 100) / 100;
    packets.originalLengthAverage = Math.round((packets.totalOriginalBytes / packets.totalPackets) * 100) / 100;
  }

  return { isPcap: true, fileSize: file.size, header, packets, linkLayer, issues };
};
