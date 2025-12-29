"use strict";

import {
  ATTACHMENTS_ID,
  CHAPTERS_ID,
  CLUSTER_ID,
  CUES_ID,
  INFO_ID,
  INITIAL_SCAN_BYTES,
  SEEK_HEAD_ID,
  TAGS_ID,
  TRACKS_ID
} from "./constants.js";
import {
  readElementAt,
  readElementHeader,
} from "./ebml.js";
import type { EbmlElementHeader } from "./ebml.js";
import type { Issues, WebmSeekHead, WebmSegment } from "./types.js";
import { parseSeekHead } from "./seek-head.js";
import { parseInfo } from "./info.js";
import { parseTracks } from "./tracks.js";
import { parseCues } from "./cues.js";
import { countBlocksInCluster } from "./cluster.js";
import { parseTags } from "./tags.js";
import { parseAttachments } from "./attachments.js";

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
    attachments: null,
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
  const seekIds = new Set(
    (seekHead?.entries || []).filter(entry => entry.absoluteOffset != null).map(entry => entry.id)
  );
  const hasCues = ids.has(CUES_ID) || seekIds.has(CUES_ID) || segment.cues != null;
  const hasAttachments = ids.has(ATTACHMENTS_ID) || seekIds.has(ATTACHMENTS_ID);
  const hasTags = ids.has(TAGS_ID) || seekIds.has(TAGS_ID);
  const hasChapters = ids.has(CHAPTERS_ID) || seekIds.has(CHAPTERS_ID);
  if (!hasCues) {
    issues.push("Cues element not found; seeking metadata may be missing.");
  }
  if (docTypeLower === "webm") {
    if (hasAttachments) issues.push("Attachments element present; invalid for WebM.");
    if (hasTags) issues.push("Tags element present; invalid for WebM.");
    if (hasChapters) issues.push("Chapters element present; invalid for WebM.");
  }

  if (hasAttachments) {
    const attachmentsHeader =
      scan.scanned.find(element => element.id === ATTACHMENTS_ID) ||
      seekHead?.entries.find(entry => entry.id === ATTACHMENTS_ID && entry.absoluteOffset != null) ||
      null;
    const attachmentsOffset = attachmentsHeader
      ? "offset" in attachmentsHeader
        ? attachmentsHeader.offset
        : attachmentsHeader.absoluteOffset
      : null;
    if (attachmentsOffset != null) {
      const resolved = await readElementAt(file, attachmentsOffset, issues);
      if (resolved && resolved.id === ATTACHMENTS_ID) {
        segment.attachments = await parseAttachments(file, resolved, issues);
      }
    }
  }

  if (hasTags) {
    const tagHeader =
      scan.scanned.find(element => element.id === TAGS_ID) ||
      seekHead?.entries.find(entry => entry.id === TAGS_ID && entry.absoluteOffset != null) ||
      null;
    const tagsOffset = tagHeader
      ? "offset" in tagHeader
        ? tagHeader.offset
        : tagHeader.absoluteOffset
      : null;
    if (tagsOffset != null) {
      const resolved = await readElementAt(file, tagsOffset, issues);
      if (resolved && resolved.id === TAGS_ID) segment.tags = await parseTags(file, resolved, issues);
    }
  }

  return segment;
};
