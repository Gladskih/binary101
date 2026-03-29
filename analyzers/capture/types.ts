"use strict";

export type PcapTrafficStats = {
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
  timestampMinSeconds: number | null;
  timestampMaxSeconds: number | null;
  outOfOrderTimestamps: number;
};

export type PcapPacketStats = PcapTrafficStats & {
  truncatedFile: boolean;
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
