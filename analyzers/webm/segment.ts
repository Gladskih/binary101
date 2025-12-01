"use strict";

import {
  ATTACHMENTS_ID,
  CHAPTERS_ID,
  CLUSTER_ID,
  CUES_ID,
  INFO_ID,
  INITIAL_SCAN_BYTES,
  MAX_SEEK_BYTES,
  SEGMENT_ID,
  SEEK_ENTRY_ID,
  SEEK_HEAD_ID,
  SEEK_ID_ID,
  SEEK_POSITION_ID,
  TAGS_ID,
  TRACKS_ID
} from "./constants.js";
import {
  clampReadLength,
  readElementAt,
  readElementHeader,
  readUnsigned
} from "./ebml.js";
import type { EbmlElementHeader } from "./ebml.js";
import type { Issues, WebmSeekHead, WebmSegment } from "./types.js";
import { parseInfo } from "./info.js";
import { parseTracks } from "./tracks.js";
import { parseCues } from "./cues.js";
import { countBlocksInCluster } from "./cluster.js";
import { parseTags } from "./tags.js";

const describeElement = (id: number): string => {
  switch (id) {
    case SEGMENT_ID:
      return "Segment";
    case INFO_ID:
      return "Segment Info";
    case TRACKS_ID:
      return "Tracks";
    case SEEK_HEAD_ID:
      return "SeekHead";
    default:
      return `0x${id.toString(16)}`;
  }
};

type SegmentScanResult = {
  infoHeader: EbmlElementHeader | null;
  tracksHeader: EbmlElementHeader | null;
  seekHeaders: EbmlElementHeader[];
  scanned: Array<{ id: number; offset: number; size: number | null }>;
  issues: string[];
  bytesScanned: number;
  hitLimit: boolean;
};

const scanSegment = async (
  file: File,
  segment: EbmlElementHeader,
  issues: Issues,
  scanLimit: number
): Promise<SegmentScanResult> => {
  const maxAvailable = Math.max(0, file.size - segment.dataOffset);
  const readLength = Math.min(scanLimit, segment.size ?? maxAvailable);
  const dv = new DataView(await file.slice(segment.dataOffset, segment.dataOffset + readLength).arrayBuffer());
  const result: SegmentScanResult = {
    infoHeader: null,
    tracksHeader: null,
    seekHeaders: [],
    scanned: [],
    issues: [],
    bytesScanned: readLength,
    hitLimit: segment.size != null ? readLength < segment.size : readLength < maxAvailable
  };
  let cursor = 0;
  const limit = Math.min(readLength, segment.size ?? readLength);
  while (cursor < limit) {
    const header = readElementHeader(dv, cursor, segment.dataOffset + cursor, result.issues);
    if (!header || header.headerSize === 0) break;
    result.scanned.push({ id: header.id, offset: header.offset, size: header.size });
    if (header.id === INFO_ID && !result.infoHeader) result.infoHeader = header;
    if (header.id === TRACKS_ID && !result.tracksHeader) result.tracksHeader = header;
    if (header.id === SEEK_HEAD_ID) result.seekHeaders.push(header);
    if (header.size == null || header.sizeUnknown) break;
    const next = cursor + header.headerSize + header.size;
    if (next <= cursor) break;
    cursor = next;
  }
  issues.push(...result.issues);
  return result;
};
const parseSeekHead = async (
  file: File,
  seekHead: EbmlElementHeader,
  segmentDataStart: number,
  issues: Issues
): Promise<WebmSeekHead> => {
  const { length, truncated } = clampReadLength(file.size, seekHead.dataOffset, seekHead.size, MAX_SEEK_BYTES);
  const dv = new DataView(await file.slice(seekHead.dataOffset, seekHead.dataOffset + length).arrayBuffer());
  const limit = seekHead.size != null ? Math.min(seekHead.size, dv.byteLength) : dv.byteLength;
  const entries: WebmSeekHead["entries"] = [];
  let cursor = 0;
  while (cursor < limit) {
    const entryHeader = readElementHeader(dv, cursor, seekHead.dataOffset + cursor, issues);
    if (!entryHeader || entryHeader.headerSize === 0) break;
    const dataStart = cursor + entryHeader.headerSize;
    const available = Math.min(entryHeader.size ?? 0, limit - dataStart);
    if (entryHeader.id === SEEK_ENTRY_ID && available > 0) {
      let id = 0;
      let position: number | null = null;
      let absoluteOffset: number | null = null;
      let innerCursor = dataStart;
      const entryEnd = dataStart + available;
      while (innerCursor < entryEnd) {
        const innerHeader = readElementHeader(dv, innerCursor, seekHead.dataOffset + innerCursor, issues);
        if (!innerHeader || innerHeader.headerSize === 0 || innerHeader.size == null) break;
        const innerData = innerCursor + innerHeader.headerSize;
        const innerAvailable = Math.min(innerHeader.size, entryEnd - innerData);
        if (innerHeader.id === SEEK_ID_ID && innerAvailable > 0) {
          id = new Uint8Array(dv.buffer, dv.byteOffset + innerData, innerAvailable).reduce(
            (acc, byte) => (acc << 8) | byte,
            0
          );
        } else if (innerHeader.id === SEEK_POSITION_ID && innerAvailable > 0) {
          const posValue = readUnsigned(dv, innerData, innerAvailable, issues, "SeekPosition");
          if (posValue != null) {
            const asNumber = Number(posValue);
            if (Number.isSafeInteger(asNumber)) {
              position = asNumber;
              absoluteOffset = segmentDataStart + asNumber;
            } else {
              issues.push("SeekPosition exceeds safe integer range.");
            }
          }
        }
        innerCursor += innerHeader.headerSize + innerHeader.size;
      }
      entries.push({
        id,
        name: describeElement(id),
        position,
        absoluteOffset
      });
    }
    if (entryHeader.size == null) break;
    cursor += entryHeader.headerSize + entryHeader.size;
  }
  return { entries, truncated: truncated || (seekHead.size != null && length < seekHead.size) };
};

const pickElement = (
  scan: SegmentScanResult,
  seek: WebmSeekHead | null,
  targetId: number
): EbmlElementHeader | null => {
  if (targetId === INFO_ID && scan.infoHeader) return scan.infoHeader;
  if (targetId === TRACKS_ID && scan.tracksHeader) return scan.tracksHeader;
  const candidate = seek?.entries.find(entry => entry.id === targetId && entry.absoluteOffset != null);
  if (!candidate || candidate.absoluteOffset == null) return null;
  const offset = candidate.absoluteOffset;
  return { id: targetId, size: null, headerSize: 0, dataOffset: offset, offset, sizeUnknown: true };
};
export const parseSegment = async (
  file: File,
  segmentHeader: EbmlElementHeader,
  issues: Issues,
  docTypeLower: string
): Promise<WebmSegment> => {
  const segmentSize = segmentHeader.size ?? Math.max(0, file.size - segmentHeader.dataOffset);
  const segment: WebmSegment = {
    offset: segmentHeader.offset,
    size: segmentHeader.size,
    dataOffset: segmentHeader.dataOffset,
    dataSize: segmentSize,
    info: null,
    tracks: [],
    seekHead: null,
    cues: null,
    tags: null,
    clusterCount: 0,
    blockCount: 0,
    keyframeCount: 0,
    firstClusterOffset: null,
    scannedElements: [],
    scanLimit: Math.min(INITIAL_SCAN_BYTES, segmentSize)
  };

  const initialLimit = Math.min(INITIAL_SCAN_BYTES, segmentSize);
  const initialScan = await scanSegment(file, segmentHeader, issues, initialLimit);
  let scan = initialScan;
  if ((!initialScan.infoHeader || !initialScan.tracksHeader) && segmentSize > initialLimit) {
    const fullScan = await scanSegment(file, segmentHeader, issues, segmentSize);
    scan = fullScan;
    segment.scanLimit = fullScan.bytesScanned;
  } else {
    segment.scanLimit = initialScan.bytesScanned;
  }
  segment.scannedElements = scan.scanned;
  const clusters = scan.scanned.filter(element => element.id === CLUSTER_ID);
  segment.clusterCount = clusters.length;
  if (clusters.length > 0) {
    segment.firstClusterOffset = clusters[0]?.offset ?? null;
  }
  for (const cluster of clusters) {
    const resolvedCluster = await readElementAt(file, cluster.offset, issues);
    if (!resolvedCluster || resolvedCluster.id !== CLUSTER_ID) continue;
    const stats = await countBlocksInCluster(file, resolvedCluster, issues);
    segment.blockCount += stats.blocks;
    segment.keyframeCount += stats.keyframes;
  }
  let seekHead: WebmSeekHead | null = null;
  const [firstSeek] = scan.seekHeaders;
  if (firstSeek) {
    seekHead = await parseSeekHead(file, firstSeek, segmentHeader.dataOffset, issues);
    segment.seekHead = seekHead;
  }

  const infoHeader =
    scan.infoHeader ||
    pickElement(scan, seekHead, INFO_ID) ||
    null;
  if (infoHeader) {
    const resolved = infoHeader.headerSize
      ? infoHeader
      : await readElementAt(file, infoHeader.offset, issues);
    if (resolved && resolved.id === INFO_ID) {
      segment.info = await parseInfo(file, resolved, 1000000, issues);
    }
  }

  const tracksHeader =
    scan.tracksHeader ||
    pickElement(scan, seekHead, TRACKS_ID) ||
    null;
  if (tracksHeader) {
    const resolved = tracksHeader.headerSize
      ? tracksHeader
      : await readElementAt(file, tracksHeader.offset, issues);
    if (resolved && resolved.id === TRACKS_ID) {
      segment.tracks = await parseTracks(file, resolved, issues);
    }
  }
  if (docTypeLower === "webm") {
    const allowed = new Set(["V_VP8", "V_VP9", "V_AV1", "A_VORBIS", "A_OPUS"]);
    for (const track of segment.tracks) {
      if (track.codecId) {
        const isAllowed = allowed.has(track.codecId);
        track.codecIdValidForWebm = isAllowed;
        if (!isAllowed) {
          issues.push(`CodecID ${track.codecId} is not allowed in WebM.`);
        }
      }
    }
  }

  let cuesHeader: EbmlElementHeader | null = null;
  const scannedCue = scan.scanned.find(element => element.id === CUES_ID);
  if (scannedCue) {
    cuesHeader = await readElementAt(file, scannedCue.offset, issues);
  } else if (seekHead) {
    const cueEntry = seekHead.entries.find(entry => entry.id === CUES_ID && entry.absoluteOffset != null);
    if (cueEntry?.absoluteOffset != null) {
      cuesHeader = await readElementAt(file, cueEntry.absoluteOffset, issues);
    }
  }
  if (cuesHeader && cuesHeader.id === CUES_ID) {
    segment.cues = await parseCues(file, cuesHeader, issues, segment.info?.timecodeScale ?? 1000000);
  }

  if ((!scan.infoHeader || !scan.tracksHeader) && scan.hitLimit && segmentHeader.size == null) {
    issues.push(
      `Segment scanning stopped after ${scan.bytesScanned} bytes; segment size is unknown so some metadata may be missing.`
    );
  }

  const ids = new Set(scan.scanned.map(element => element.id));
  const hasCues = ids.has(CUES_ID) || segment.cues != null;
  const hasAttachments = ids.has(ATTACHMENTS_ID);
  const hasTags = ids.has(TAGS_ID);
  const hasChapters = ids.has(CHAPTERS_ID);
  if (!hasCues) {
    issues.push("Cues element not found; seeking metadata may be missing.");
  }
  if (docTypeLower === "webm") {
    if (hasAttachments) issues.push("Attachments element present; invalid for WebM.");
    if (hasTags) issues.push("Tags element present; invalid for WebM.");
    if (hasChapters) issues.push("Chapters element present; invalid for WebM.");
  }

  if (hasTags) {
    const tagHeader = scan.scanned.find(element => element.id === TAGS_ID);
    if (tagHeader) {
      const resolved = await readElementAt(file, tagHeader.offset, issues);
      if (resolved && resolved.id === TAGS_ID) segment.tags = await parseTags(file, resolved, issues);
    }
  }

  return segment;
};
