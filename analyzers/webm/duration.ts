"use strict";

import { CLUSTER_ID } from "./constants.js";
import { readElementAt } from "./ebml.js";
import type { EbmlElementHeader } from "./ebml.js";
import { countBlocksInCluster } from "./cluster.js";
import type { Issues, WebmComputedDuration, WebmComputedTrackDuration, WebmTrack } from "./types.js";

type TrackTimingState = {
  startsNs: number[];
  maxEndNs: number | null;
  blockCount: number;
};

const NANOSECONDS_PER_SECOND = 1e9;

const median = (values: number[]): number | null => {
  if (values.length === 0) return null;
  const sorted = [...values].sort((a, b) => a - b);
  return sorted[Math.floor(sorted.length / 2)] ?? null;
};

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
}> => {
  const tracksByNumber = new Map<number, WebmTrack>();
  for (const track of tracks) {
    if (track.trackNumber != null) tracksByNumber.set(track.trackNumber, track);
  }
  const trackStates = new Map<number, TrackTimingState>();

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
          const track = tracksByNumber.get(timing.trackNumber) ?? null;
          if (track?.defaultDuration != null && Number.isFinite(track.defaultDuration) && track.defaultDuration > 0) {
            const frames = timing.frames > 0 ? timing.frames : 1;
            endNs = startNs + track.defaultDuration * frames;
          }
        }
        if (endNs != null && Number.isFinite(endNs)) {
          state.maxEndNs = state.maxEndNs == null ? endNs : Math.max(state.maxEndNs, endNs);
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
    computedDuration: computeComputedDuration(trackStates, tracksByNumber, timecodeScaleNs)
  };
};

