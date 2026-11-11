"use strict";

import { CLUSTER_ID } from "./constants.js";
import { scanCluster } from "./cluster.js";
import type { OnClusterBlock } from "./cluster-block.js";
import { createEbmlStreamReader, type EbmlScanReader } from "./ebml-stream.js";
import { EBML_SCAN_WINDOW_BYTES, EbmlRangeReader } from "./ebml-range.js";
import type { EbmlElementHeader } from "./ebml.js";
import type { Issues, WebmScanControl } from "./types.js";

export type SegmentClusterScan = {
  clusterCount: number;
  blockCount: number;
  keyframeCount: number;
  firstClusterOffset: number | null;
};

const skipTopLevelElement = async (
  reader: EbmlScanReader,
  header: EbmlElementHeader,
  segmentEnd: number,
  issues: Issues
): Promise<boolean> => {
  if (header.size == null) {
    issues.push(`Top-level element at ${header.offset} has unknown size; cluster scan stopped.`);
    return false;
  }
  const available = Math.max(0, segmentEnd - header.dataOffset);
  const size = Math.min(header.size, available);
  if (header.size > available) {
    issues.push(`Top-level element at ${header.offset} extends beyond the Segment.`);
  }
  const skipped = await reader.skip(size);
  if (skipped < size) issues.push(`Top-level element at ${header.offset} is truncated.`);
  return skipped === size;
};

const describeError = (error: unknown): string =>
  error instanceof Error && error.message ? error.message : String(error);

export const scanSegmentClusters = async (
  file: File,
  segmentHeader: EbmlElementHeader,
  segmentSize: number,
  issues: Issues,
  onBlock: OnClusterBlock,
  control?: WebmScanControl
): Promise<SegmentClusterScan> => {
  const available = Math.max(0, file.size - segmentHeader.dataOffset);
  const segmentEnd = segmentHeader.dataOffset + Math.min(Math.max(0, segmentSize), available);
  let reader: EbmlScanReader | null = null;
  let pendingHeader: EbmlElementHeader | null = null;
  let clusterCount = 0;
  let blockCount = 0;
  let keyframeCount = 0;
  let firstClusterOffset: number | null = null;
  try {
    reader = segmentEnd - segmentHeader.dataOffset > EBML_SCAN_WINDOW_BYTES
      ? new EbmlRangeReader(file, segmentHeader.dataOffset, segmentEnd, control?.signal)
      : createEbmlStreamReader(file, segmentHeader.dataOffset, segmentEnd, control?.signal);
    while (reader.offset < segmentEnd) {
      const header = pendingHeader ?? await reader.readElementHeader(segmentEnd, issues);
      pendingHeader = null;
      if (!header) break;
      if (header.id !== CLUSTER_ID) {
        if (!await skipTopLevelElement(reader, header, segmentEnd, issues)) break;
        continue;
      }
      clusterCount++;
      if (firstClusterOffset == null) firstClusterOffset = header.offset;
      const cluster = await scanCluster(reader, header, segmentEnd, issues, onBlock);
      control?.signal.throwIfAborted();
      control?.onProgress(reader.offset - segmentHeader.dataOffset, segmentEnd - segmentHeader.dataOffset);
      blockCount += cluster.blocks;
      keyframeCount += cluster.keyframes;
      pendingHeader = cluster.nextHeader;
      if (cluster.stopSegment) break;
    }
  } catch (error) {
    control?.signal.throwIfAborted();
    issues.push(`Sequential Segment scan failed: ${describeError(error)}.`);
  } finally {
    await reader?.cancel?.();
  }
  return { clusterCount, blockCount, keyframeCount, firstClusterOffset };
};
