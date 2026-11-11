"use strict";

import {
  ATTACHMENTS_ID,
  BLOCK_DURATION_ID,
  BLOCK_GROUP_ID,
  BLOCK_ID,
  CHAPTERS_ID,
  CLUSTER_ID,
  CLUSTER_TIMECODE_ID,
  CUES_ID,
  INFO_ID,
  MAX_EBML_INTEGER_BYTES,
  REFERENCE_BLOCK_ID,
  SEEK_HEAD_ID,
  SIMPLE_BLOCK_ID,
  TAGS_ID,
  TRACKS_ID
} from "./constants.js";
import {
  BLOCK_ANALYSIS_PREFIX_BYTES,
  emitStreamBlockTiming,
  MIN_BLOCK_HEADER_BYTES,
  parseStreamBlockHeader,
  WEBM_BLOCK_FLAGS
} from "./cluster-block.js";
import type { OnClusterBlock, WebmBlockHeader } from "./cluster-block.js";
import type { EbmlStreamReader } from "./ebml-stream.js";
import { readUnsigned } from "./ebml.js";
import type { EbmlElementHeader } from "./ebml.js";
import type { Issues } from "./types.js";

type ClusterScan = {
  blocks: number;
  keyframes: number;
  nextHeader: EbmlElementHeader | null;
  stopSegment: boolean;
};

const SEGMENT_LEVEL_IDS = new Set([
  ATTACHMENTS_ID,
  CHAPTERS_ID,
  CLUSTER_ID,
  CUES_ID,
  INFO_ID,
  SEEK_HEAD_ID,
  TAGS_ID,
  TRACKS_ID
]);

const boundedSize = (
  header: EbmlElementHeader,
  endOffset: number,
  issues: Issues,
  label: string
): number | null => {
  if (header.size == null) {
    issues.push(`${label} at ${header.offset} has unknown size.`);
    return null;
  }
  const available = Math.max(0, endOffset - header.dataOffset);
  if (header.size > available) issues.push(`${label} at ${header.offset} is truncated.`);
  return Math.min(header.size, available);
};

const readUnsignedElement = async (
  reader: EbmlStreamReader,
  header: EbmlElementHeader,
  endOffset: number,
  issues: Issues,
  label: string
): Promise<number | null> => {
  const size = boundedSize(header, endOffset, issues, label);
  if (size == null) return null;
  const expectedBytes = Math.min(size, MAX_EBML_INTEGER_BYTES);
  const bytes = await reader.readBytes(expectedBytes);
  const skipped = await reader.skip(size - bytes.byteLength);
  if (bytes.byteLength < expectedBytes || bytes.byteLength + skipped < size) {
    issues.push(`${label} at ${header.offset} is truncated.`);
    return null;
  }
  if (size > MAX_EBML_INTEGER_BYTES) {
    issues.push(`${label} uses unsupported integer size ${size}.`);
    return null;
  }
  const value = readUnsigned(
    new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength),
    0,
    bytes.byteLength,
    issues,
    label
  );
  if (value == null) return null;
  const numeric = Number(value);
  if (Number.isSafeInteger(numeric)) return numeric;
  issues.push(`${label} exceeds safe integer range.`);
  return null;
};

const skipElement = async (
  reader: EbmlStreamReader,
  header: EbmlElementHeader,
  endOffset: number,
  issues: Issues
): Promise<boolean> => {
  const size = boundedSize(header, endOffset, issues, "Cluster child");
  return size != null && await reader.skip(size) === size;
};

const scanBlockGroup = async (
  reader: EbmlStreamReader,
  header: EbmlElementHeader,
  clusterEnd: number,
  issues: Issues,
  clusterTimecode: number | null,
  onBlock: OnClusterBlock
): Promise<{ blocks: number; keyframes: number; complete: boolean }> => {
  const size = boundedSize(header, clusterEnd, issues, "BlockGroup");
  if (size == null) return { blocks: 0, keyframes: 0, complete: false };
  const groupEnd = header.dataOffset + size;
  let block: WebmBlockHeader | null = null;
  let blockData: Uint8Array<ArrayBufferLike> = new Uint8Array(0);
  let blocks = 0;
  let hasReference = false;
  let durationTimecode: number | null = null;
  while (reader.offset < groupEnd) {
    const child = await reader.readElementHeader(groupEnd, issues);
    if (!child) return { blocks, keyframes: 0, complete: false };
    if (child.id === BLOCK_ID) {
      const childSize = boundedSize(child, groupEnd, issues, "Block");
      if (childSize == null) return { blocks, keyframes: 0, complete: false };
      blockData = await reader.readBytes(Math.min(childSize, BLOCK_ANALYSIS_PREFIX_BYTES));
      await reader.skip(childSize - blockData.byteLength);
      if (childSize < MIN_BLOCK_HEADER_BYTES) {
        issues.push(`Block at ${child.offset} is too short.`);
      }
      block = childSize >= MIN_BLOCK_HEADER_BYTES
        ? parseStreamBlockHeader(blockData, issues)
        : null;
      blocks++;
    } else if (child.id === REFERENCE_BLOCK_ID) {
      hasReference = true;
      if (!await skipElement(reader, child, groupEnd, issues)) {
        return { blocks, keyframes: 0, complete: false };
      }
    } else if (child.id === BLOCK_DURATION_ID) {
      durationTimecode = await readUnsignedElement(
        reader,
        child,
        groupEnd,
        issues,
        "BlockDuration"
      );
    } else if (!await skipElement(reader, child, groupEnd, issues)) {
      return { blocks, keyframes: 0, complete: false };
    }
  }
  const isKeyframe = block != null && !hasReference;
  if (block) {
    emitStreamBlockTiming(block, blockData, clusterTimecode, durationTimecode, isKeyframe, onBlock);
  }
  return { blocks, keyframes: Number(isKeyframe), complete: true };
};

export const scanCluster = async (
  reader: EbmlStreamReader,
  clusterHeader: EbmlElementHeader,
  segmentEnd: number,
  issues: Issues,
  onBlock: OnClusterBlock
): Promise<ClusterScan> => {
  const declaredSize = clusterHeader.size;
  const available = Math.max(0, segmentEnd - clusterHeader.dataOffset);
  const unknownSize = declaredSize == null;
  const clusterEnd = declaredSize == null
    ? segmentEnd
    : clusterHeader.dataOffset + Math.min(declaredSize, available);
  if (declaredSize != null && declaredSize > available) {
    issues.push(`Cluster at ${clusterHeader.offset} extends beyond the Segment.`);
  }
  let blocks = 0;
  let keyframes = 0;
  let clusterTimecode: number | null = null;
  while (reader.offset < clusterEnd) {
    const header = await reader.readElementHeader(clusterEnd, issues);
    if (!header) return { blocks, keyframes, nextHeader: null, stopSegment: true };
    if (unknownSize && SEGMENT_LEVEL_IDS.has(header.id)) {
      return { blocks, keyframes, nextHeader: header, stopSegment: false };
    }
    if (header.id === CLUSTER_TIMECODE_ID) {
      clusterTimecode = await readUnsignedElement(
        reader,
        header,
        clusterEnd,
        issues,
        "ClusterTimecode"
      );
    } else if (header.id === SIMPLE_BLOCK_ID) {
      const size = boundedSize(header, clusterEnd, issues, "SimpleBlock");
      if (size == null) return { blocks, keyframes, nextHeader: null, stopSegment: true };
      const data = await reader.readBytes(Math.min(size, BLOCK_ANALYSIS_PREFIX_BYTES));
      await reader.skip(size - data.byteLength);
      if (size >= MIN_BLOCK_HEADER_BYTES) {
        const block = parseStreamBlockHeader(data, issues);
        const isKeyframe =
          block.flags != null && (block.flags & WEBM_BLOCK_FLAGS.keyframe) !== 0;
        blocks++;
        if (isKeyframe) keyframes++;
        emitStreamBlockTiming(block, data, clusterTimecode, null, isKeyframe, onBlock);
      } else {
        issues.push(`SimpleBlock at ${header.offset} is too short.`);
      }
    } else if (header.id === BLOCK_GROUP_ID) {
      const group = await scanBlockGroup(
        reader,
        header,
        clusterEnd,
        issues,
        clusterTimecode,
        onBlock
      );
      blocks += group.blocks;
      keyframes += group.keyframes;
      if (!group.complete) return { blocks, keyframes, nextHeader: null, stopSegment: true };
    } else if (!await skipElement(reader, header, clusterEnd, issues)) {
      return { blocks, keyframes, nextHeader: null, stopSegment: true };
    }
  }
  return { blocks, keyframes, nextHeader: null, stopSegment: false };
};
