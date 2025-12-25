"use strict";

export type PcapTimestampResolution = "microseconds" | "nanoseconds";

export type PcapGlobalHeader = {
  littleEndian: boolean;
  timestampResolution: PcapTimestampResolution;
  versionMajor: number | null;
  versionMinor: number | null;
  thiszone: number | null;
  sigfigs: number | null;
  snaplen: number | null;
  network: number | null;
  networkName: string | null;
};

export type PcapPacketStats = {
  totalPackets: number;
  totalCapturedBytes: number;
  totalOriginalBytes: number;
  capturedLengthMin: number | null;
  capturedLengthMax: number | null;
  capturedLengthAverage: number | null;
  originalLengthMin: number | null;
  originalLengthMax: number | null;
  originalLengthAverage: number | null;
  truncatedPackets: number;
  truncatedFile: boolean;
  timestampMinSeconds: number | null;
  timestampMaxSeconds: number | null;
  outOfOrderTimestamps: number;
};

export type PcapEthernetSummary = {
  framesParsed: number;
  vlanTaggedFrames: number;
  shortFrames: number;
  etherTypes: Map<number, number>;
  ipProtocols: Map<number, number>;
};

export type PcapLinkLayerSummary = {
  ethernet?: PcapEthernetSummary;
};

export type PcapParseResult = {
  isPcap: true;
  fileSize: number;
  header: PcapGlobalHeader;
  packets: PcapPacketStats;
  linkLayer: PcapLinkLayerSummary | null;
  issues: string[];
};

