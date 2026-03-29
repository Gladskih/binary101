"use strict";

import type { PcapLinkLayerSummary, PcapPacketStats } from "../capture/types.js";

export type {
  PcapEthernetSummary,
  PcapLinkLayerSummary,
  PcapPacketStats,
  PcapTrafficStats
} from "../capture/types.js";

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

export type PcapClassicParseResult = {
  isPcap: true;
  format: "pcap";
  fileSize: number;
  header: PcapGlobalHeader;
  packets: PcapPacketStats;
  linkLayer: PcapLinkLayerSummary | null;
  issues: string[];
};
