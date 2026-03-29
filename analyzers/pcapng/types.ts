"use strict";

import type { PcapLinkLayerSummary, PcapPacketStats, PcapTrafficStats } from "../capture/types.js";

export type {
  PcapEthernetSummary,
  PcapLinkLayerSummary,
  PcapPacketStats,
  PcapTrafficStats
} from "../capture/types.js";

export type PcapNgSectionSummary = {
  index: number;
  littleEndian: boolean;
  versionMajor: number | null;
  versionMinor: number | null;
  sectionLength: bigint | null;
  hardware: string | null;
  os: string | null;
  userAppl: string | null;
};

export type PcapNgInterfaceStatistics = {
  timestamp: bigint | null;
  captureStart: bigint | null;
  captureEnd: bigint | null;
  receivedPackets: bigint | null;
  droppedByInterface: bigint | null;
  acceptedByFilter: bigint | null;
  droppedByOs: bigint | null;
  deliveredToUser: bigint | null;
};

export type PcapNgInterfaceSummary = {
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
  timestampOffsetSeconds: bigint | null;
  observedDropCount: bigint | null;
  statistics: PcapNgInterfaceStatistics | null;
  packets: PcapTrafficStats;
};

export type PcapNgBlockSummary = {
  totalBlocks: number;
  interfaceDescriptionBlocks: number;
  enhancedPacketBlocks: number;
  simplePacketBlocks: number;
  packetBlocks: number;
  nameResolutionBlocks: number;
  interfaceStatisticsBlocks: number;
  decryptionSecretsBlocks: number;
  customBlocks: number;
  unknownBlocks: number;
};

export type PcapNgNameResolutionSummary = {
  ipv4Records: number;
  ipv6Records: number;
  otherRecords: number;
  missingEndMarkers: number;
};

export type PcapNgParseResult = {
  isPcap: true;
  format: "pcapng";
  fileSize: number;
  sections: PcapNgSectionSummary[];
  interfaces: PcapNgInterfaceSummary[];
  blocks: PcapNgBlockSummary;
  nameResolution: PcapNgNameResolutionSummary;
  packets: PcapPacketStats;
  linkLayer: PcapLinkLayerSummary | null;
  issues: string[];
};
