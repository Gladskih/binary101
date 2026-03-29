"use strict";

import type { PcapPacketStats, PcapTrafficStats } from "./types.js";

export type MutableTrafficStats = {
  totalPackets: number;
  totalCapturedBytes: number;
  totalOriginalBytes: number;
  capturedLengthMin: number | null;
  capturedLengthMax: number | null;
  originalLengthMin: number | null;
  originalLengthMax: number | null;
  truncatedPackets: number;
  timestampMinSeconds: number | null;
  timestampMaxSeconds: number | null;
  outOfOrderTimestamps: number;
  lastTimestampSeconds: number | null;
};

export const createMutableTrafficStats = (): MutableTrafficStats => ({
  totalPackets: 0,
  totalCapturedBytes: 0,
  totalOriginalBytes: 0,
  capturedLengthMin: null,
  capturedLengthMax: null,
  originalLengthMin: null,
  originalLengthMax: null,
  truncatedPackets: 0,
  timestampMinSeconds: null,
  timestampMaxSeconds: null,
  outOfOrderTimestamps: 0,
  lastTimestampSeconds: null
});

export const observePacket = (
  stats: MutableTrafficStats,
  capturedLength: number,
  originalLength: number,
  timestampSeconds: number | null
): void => {
  stats.totalPackets += 1;
  stats.totalCapturedBytes += capturedLength;
  stats.totalOriginalBytes += originalLength;
  if (stats.capturedLengthMin == null || capturedLength < stats.capturedLengthMin) {
    stats.capturedLengthMin = capturedLength;
  }
  if (stats.capturedLengthMax == null || capturedLength > stats.capturedLengthMax) {
    stats.capturedLengthMax = capturedLength;
  }
  if (stats.originalLengthMin == null || originalLength < stats.originalLengthMin) {
    stats.originalLengthMin = originalLength;
  }
  if (stats.originalLengthMax == null || originalLength > stats.originalLengthMax) {
    stats.originalLengthMax = originalLength;
  }
  if (originalLength > capturedLength) stats.truncatedPackets += 1;
  if (timestampSeconds == null) return;
  if (stats.timestampMinSeconds == null || timestampSeconds < stats.timestampMinSeconds) {
    stats.timestampMinSeconds = timestampSeconds;
  }
  if (stats.timestampMaxSeconds == null || timestampSeconds > stats.timestampMaxSeconds) {
    stats.timestampMaxSeconds = timestampSeconds;
  }
  if (stats.lastTimestampSeconds != null && timestampSeconds < stats.lastTimestampSeconds) {
    stats.outOfOrderTimestamps += 1;
  }
  stats.lastTimestampSeconds = timestampSeconds;
};

export const finalizeTrafficStats = (stats: MutableTrafficStats): PcapTrafficStats => ({
  totalPackets: stats.totalPackets,
  totalCapturedBytes: stats.totalCapturedBytes,
  totalOriginalBytes: stats.totalOriginalBytes,
  capturedLengthMin: stats.capturedLengthMin,
  capturedLengthMax: stats.capturedLengthMax,
  capturedLengthAverage:
    stats.totalPackets > 0 ? stats.totalCapturedBytes / stats.totalPackets : null,
  originalLengthMin: stats.originalLengthMin,
  originalLengthMax: stats.originalLengthMax,
  originalLengthAverage:
    stats.totalPackets > 0 ? stats.totalOriginalBytes / stats.totalPackets : null,
  truncatedPackets: stats.truncatedPackets,
  timestampMinSeconds: stats.timestampMinSeconds,
  timestampMaxSeconds: stats.timestampMaxSeconds,
  outOfOrderTimestamps: stats.outOfOrderTimestamps
});

export const finalizePacketStats = (
  stats: MutableTrafficStats,
  truncatedFile: boolean
): PcapPacketStats => ({
  ...finalizeTrafficStats(stats),
  truncatedFile
});
