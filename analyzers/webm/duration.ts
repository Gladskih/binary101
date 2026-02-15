"use strict";

import { CLUSTER_ID } from "./constants.js";
import { readElementAt } from "./ebml.js";
import type { EbmlElementHeader } from "./ebml.js";
import { countBlocksInCluster } from "./cluster.js";
import type {
  Issues,
  WebmComputedDuration,
  WebmComputedTrackDuration,
  WebmTrack,
  WebmTrackBitstreamFrameStats
} from "./types.js";

type TrackTimingState = {
  startsNs: number[];
  maxEndNs: number | null;
  blockCount: number;
};

type VideoFrameSizeState = {
  blockCount: number;
  keyframeCount: number;
  parsedFrameCount: number;
  mismatchWithTrackEntryCount: number;
  minWidth: number | null;
  maxWidth: number | null;
  minHeight: number | null;
  maxHeight: number | null;
  sizeCounts: Map<string, { width: number; height: number; count: number }>;
};

const NANOSECONDS_PER_SECOND = 1e9;
const VP8_CODEC_ID = "V_VP8";

const median = (values: number[]): number | null => {
  if (values.length === 0) return null;
  const sorted = [...values].sort((a, b) => a - b);
  return sorted[Math.floor(sorted.length / 2)] ?? null;
};

const createVideoFrameSizeState = (): VideoFrameSizeState => ({
  blockCount: 0,
  keyframeCount: 0,
  parsedFrameCount: 0,
  mismatchWithTrackEntryCount: 0,
  minWidth: null,
  maxWidth: null,
  minHeight: null,
  maxHeight: null,
  sizeCounts: new Map()
});

const parseVp8KeyframeSize = (payload: Uint8Array): { width: number; height: number } | null => {
  if (payload.length < 10) return null;
  const b0 = payload[0] ?? 0;
  const b1 = payload[1] ?? 0;
  const b2 = payload[2] ?? 0;
  const b3 = payload[3] ?? 0;
  const b4 = payload[4] ?? 0;
  const b5 = payload[5] ?? 0;
  const b6 = payload[6] ?? 0;
  const b7 = payload[7] ?? 0;
  const b8 = payload[8] ?? 0;
  const b9 = payload[9] ?? 0;
  const frameTag = b0 | (b1 << 8) | (b2 << 16);
  const frameType = frameTag & 0x01;
  if (frameType !== 0) return null;
  if (b3 !== 0x9d || b4 !== 0x01 || b5 !== 0x2a) return null;
  const packedWidth = b6 | (b7 << 8);
  const packedHeight = b8 | (b9 << 8);
  const width = packedWidth & 0x3fff;
  const height = packedHeight & 0x3fff;
  if (width <= 0 || height <= 0) return null;
  return { width, height };
};

const buildTrackFrameStats = (
  states: Map<number, VideoFrameSizeState>
): WebmTrackBitstreamFrameStats[] =>
  [...states.entries()]
    .map(([trackNumber, state]) => {
      const uniqueSizes = [...state.sizeCounts.values()].sort(
        (left, right) =>
          right.count - left.count ||
          left.width - right.width ||
          left.height - right.height
      );
      return {
        trackNumber,
        blockCount: state.blockCount,
        keyframeCount: state.keyframeCount,
        parsedFrameCount: state.parsedFrameCount,
        uniqueSizes,
        minWidth: state.minWidth,
        maxWidth: state.maxWidth,
        minHeight: state.minHeight,
        maxHeight: state.maxHeight,
        mismatchWithTrackEntryCount: state.mismatchWithTrackEntryCount,
        allBlocksAreKeyframes: state.blockCount > 0 ? state.blockCount === state.keyframeCount : null
      };
    })
    .sort((left, right) => left.trackNumber - right.trackNumber);

const computeComputedDuration = (
  trackStates: Map<number, TrackTimingState>,
  tracksByNumber: Map<number, WebmTrack>,
  timecodeScaleNs: number
): WebmComputedDuration | null => {
  if (!Number.isFinite(timecodeScaleNs) || timecodeScaleNs <= 0) return null;
  const trackNumbers = [...trackStates.keys()].sort((a, b) => a - b);
  const computedTracks: WebmComputedTrackDuration[] = [];
  let videoSeconds: number | null = null;
  let audioSeconds: number | null = null;
  for (const trackNumber of trackNumbers) {
    const state = trackStates.get(trackNumber);
    if (!state || state.startsNs.length === 0) continue;
    const starts = [...state.startsNs].sort((a, b) => a - b);
    const lastStartNs = starts[starts.length - 1] ?? null;
    if (lastStartNs == null || !Number.isFinite(lastStartNs)) continue;

    const deltas: number[] = [];
    for (let index = 1; index < starts.length; index += 1) {
      const delta = (starts[index] ?? 0) - (starts[index - 1] ?? 0);
      if (Number.isFinite(delta) && delta > 0) deltas.push(delta);
    }
    const typicalDeltaNs = median(deltas);

    const track = tracksByNumber.get(trackNumber) ?? null;
    const fallbackDurationNs =
      track?.defaultDuration != null && Number.isFinite(track.defaultDuration) && track.defaultDuration > 0
        ? track.defaultDuration
        : typicalDeltaNs ?? 0;
    const estimatedEndNs = lastStartNs + fallbackDurationNs;
    const endNs = Math.max(state.maxEndNs ?? -Infinity, estimatedEndNs);
    const durationSeconds = Number.isFinite(endNs) && endNs > 0 ? endNs / NANOSECONDS_PER_SECOND : 0;

    computedTracks.push({
      trackNumber,
      trackType: track?.trackType ?? null,
      trackTypeLabel: track?.trackTypeLabel ?? "Unknown",
      codecId: track?.codecId ?? null,
      durationSeconds
    });

    if (track?.trackType === 1) {
      videoSeconds = videoSeconds == null ? durationSeconds : Math.max(videoSeconds, durationSeconds);
    } else if (track?.trackType === 2) {
      audioSeconds = audioSeconds == null ? durationSeconds : Math.max(audioSeconds, durationSeconds);
    }
  }
  const overallSeconds =
    videoSeconds == null && audioSeconds == null
      ? null
      : Math.max(videoSeconds ?? 0, audioSeconds ?? 0);
  return { overallSeconds, videoSeconds, audioSeconds, tracks: computedTracks };
};

export const scanSegmentForComputedDuration = async (
  file: File,
  segmentHeader: EbmlElementHeader,
  segmentSize: number,
  timecodeScaleNs: number,
  tracks: WebmTrack[],
  issues: Issues
): Promise<{
  clusterCount: number;
  blockCount: number;
  keyframeCount: number;
  firstClusterOffset: number | null;
  computedDuration: WebmComputedDuration | null;
  trackFrameStats: WebmTrackBitstreamFrameStats[];
}> => {
  const tracksByNumber = new Map<number, WebmTrack>();
  for (const track of tracks) {
    if (track.trackNumber != null) tracksByNumber.set(track.trackNumber, track);
  }
  const trackStates = new Map<number, TrackTimingState>();
  const frameSizeStates = new Map<number, VideoFrameSizeState>();

  const segmentEnd = Math.min(file.size, segmentHeader.dataOffset + Math.max(0, segmentSize));
  let cursor = segmentHeader.dataOffset;
  let clusterCount = 0;
  let blockCount = 0;
  let keyframeCount = 0;
  let firstClusterOffset: number | null = null;

  while (cursor < segmentEnd) {
    const header = await readElementAt(file, cursor, issues);
    if (!header || header.headerSize === 0) break;
    if (header.id === CLUSTER_ID) {
      clusterCount += 1;
      if (firstClusterOffset == null) firstClusterOffset = header.offset;
      const size = header.size ?? Math.max(0, segmentEnd - header.dataOffset);
      const resolvedCluster: EbmlElementHeader = {
        ...header,
        size,
        sizeUnknown: false
      };
      const stats = await countBlocksInCluster(file, resolvedCluster, issues, timing => {
        if (timing.trackNumber == null || timing.timecode == null) return;
        const track = tracksByNumber.get(timing.trackNumber) ?? null;
        const startNs = timing.timecode * timecodeScaleNs;
        if (!Number.isFinite(startNs)) {
          issues.push("Block timecode exceeds representable range.");
          return;
        }
        let state = trackStates.get(timing.trackNumber);
        if (!state) {
          state = { startsNs: [], maxEndNs: null, blockCount: 0 };
          trackStates.set(timing.trackNumber, state);
        }
        state.startsNs.push(startNs);
        state.blockCount += 1;

        let endNs: number | null = null;
        if (timing.durationTimecode != null) {
          const durationNs = timing.durationTimecode * timecodeScaleNs;
          endNs = startNs + durationNs;
        } else {
          if (track?.defaultDuration != null && Number.isFinite(track.defaultDuration) && track.defaultDuration > 0) {
            const frames = timing.frames > 0 ? timing.frames : 1;
            endNs = startNs + track.defaultDuration * frames;
          }
        }
        if (endNs != null && Number.isFinite(endNs)) {
          state.maxEndNs = state.maxEndNs == null ? endNs : Math.max(state.maxEndNs, endNs);
        }

        if (track?.trackType !== 1 || track.codecId !== VP8_CODEC_ID) return;
        let frameState = frameSizeStates.get(timing.trackNumber);
        if (!frameState) {
          frameState = createVideoFrameSizeState();
          frameSizeStates.set(timing.trackNumber, frameState);
        }
        frameState.blockCount += 1;
        if (timing.isKeyframe) frameState.keyframeCount += 1;
        if (!timing.isKeyframe) return;
        if (timing.lacingMode != null && timing.lacingMode !== 0) return;
        if (!timing.payload || timing.payload.length < 10) return;
        const parsedSize = parseVp8KeyframeSize(timing.payload);
        if (!parsedSize) return;
        frameState.parsedFrameCount += 1;
        const key = `${parsedSize.width}x${parsedSize.height}`;
        const existing = frameState.sizeCounts.get(key);
        if (existing) {
          existing.count += 1;
        } else {
          frameState.sizeCounts.set(key, { width: parsedSize.width, height: parsedSize.height, count: 1 });
        }
        frameState.minWidth =
          frameState.minWidth == null ? parsedSize.width : Math.min(frameState.minWidth, parsedSize.width);
        frameState.maxWidth =
          frameState.maxWidth == null ? parsedSize.width : Math.max(frameState.maxWidth, parsedSize.width);
        frameState.minHeight =
          frameState.minHeight == null ? parsedSize.height : Math.min(frameState.minHeight, parsedSize.height);
        frameState.maxHeight =
          frameState.maxHeight == null ? parsedSize.height : Math.max(frameState.maxHeight, parsedSize.height);
        if (
          track.video?.pixelWidth != null &&
          track.video.pixelHeight != null &&
          (parsedSize.width !== track.video.pixelWidth || parsedSize.height !== track.video.pixelHeight)
        ) {
          frameState.mismatchWithTrackEntryCount += 1;
        }
      });
      blockCount += stats.blocks;
      keyframeCount += stats.keyframes;
      if (header.size == null || header.sizeUnknown) break;
      const next = header.dataOffset + (header.size ?? 0);
      if (next <= cursor) break;
      cursor = next;
      continue;
    }
    if (header.size == null || header.sizeUnknown) break;
    const next = header.dataOffset + header.size;
    if (next <= cursor) break;
    cursor = next;
  }

  return {
    clusterCount,
    blockCount,
    keyframeCount,
    firstClusterOffset,
    computedDuration: computeComputedDuration(trackStates, tracksByNumber, timecodeScaleNs),
    trackFrameStats: buildTrackFrameStats(frameSizeStates)
  };
};
