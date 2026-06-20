"use strict";

import { VP8_KEYFRAME_HEADER_BYTES } from "./cluster-block.js";
import type { EbmlElementHeader } from "./ebml.js";
import { scanSegmentClusters } from "./segment-stream.js";
import type { Issues, WebmComputedDuration, WebmComputedTrackDuration, WebmTrack, WebmTrackBitstreamFrameStats } from "./types.js";

type TrackTimingState = { startsNs: number[]; maxEndNs: number | null; blockCount: number };

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
type SegmentDurationScanState = {
  tracksByNumber: Map<number, WebmTrack>;
  trackStates: Map<number, TrackTimingState>;
  frameSizeStates: Map<number, VideoFrameSizeState>;
  timecodeScaleNs: number;
  issues: Issues;
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
  if (payload.length < VP8_KEYFRAME_HEADER_BYTES) return null;
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
const updateTrackTiming = (
  state: SegmentDurationScanState,
  trackNumber: number,
  timecode: number,
  durationTimecode: number | null,
  frames: number
): TrackTimingState | null => {
  const startNs = timecode * state.timecodeScaleNs;
  if (!Number.isFinite(startNs)) {
    state.issues.push("Block timecode exceeds representable range.");
    return null;
  }
  let trackState = state.trackStates.get(trackNumber);
  if (!trackState) {
    trackState = { startsNs: [], maxEndNs: null, blockCount: 0 };
    state.trackStates.set(trackNumber, trackState);
  }
  trackState.startsNs.push(startNs);
  trackState.blockCount += 1;
  const track = state.tracksByNumber.get(trackNumber) ?? null;
  let endNs: number | null = null;
  if (durationTimecode != null) {
    endNs = startNs + durationTimecode * state.timecodeScaleNs;
  } else if (track?.defaultDuration != null && Number.isFinite(track.defaultDuration) && track.defaultDuration > 0) {
    endNs = startNs + track.defaultDuration * (frames > 0 ? frames : 1);
  }
  if (endNs != null && Number.isFinite(endNs)) {
    trackState.maxEndNs = trackState.maxEndNs == null ? endNs : Math.max(trackState.maxEndNs, endNs);
  }
  return trackState;
};
const updateVp8FrameSize = (
  state: SegmentDurationScanState,
  trackNumber: number,
  isKeyframe: boolean,
  lacingMode: number | null,
  payload: Uint8Array | null
): void => {
  const track = state.tracksByNumber.get(trackNumber) ?? null;
  if (track?.trackType !== 1 || track.codecId !== VP8_CODEC_ID) return;
  let frameState = state.frameSizeStates.get(trackNumber);
  if (!frameState) {
    frameState = createVideoFrameSizeState();
    state.frameSizeStates.set(trackNumber, frameState);
  }
  frameState.blockCount += 1;
  if (isKeyframe) frameState.keyframeCount += 1;
  if (
    !isKeyframe ||
    (lacingMode != null && lacingMode !== 0) ||
    !payload ||
    payload.length < VP8_KEYFRAME_HEADER_BYTES
  ) return;
  const parsedSize = parseVp8KeyframeSize(payload);
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
  const scanState: SegmentDurationScanState = {
    tracksByNumber,
    trackStates,
    frameSizeStates,
    timecodeScaleNs,
    issues
  };

  const clusters = await scanSegmentClusters(
    file,
    segmentHeader,
    segmentSize,
    issues,
    timing => {
      if (timing.trackNumber == null || timing.timecode == null) return;
      updateTrackTiming(
        scanState,
        timing.trackNumber,
        timing.timecode,
        timing.durationTimecode,
        timing.frames
      );
      updateVp8FrameSize(
        scanState,
        timing.trackNumber,
        timing.isKeyframe,
        timing.lacingMode,
        timing.payload
      );
    }
  );
  return {
    ...clusters,
    computedDuration: computeComputedDuration(trackStates, tracksByNumber, timecodeScaleNs),
    trackFrameStats: buildTrackFrameStats(frameSizeStates)
  };
};
