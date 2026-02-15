"use strict";

import { scanSegmentForComputedDuration } from "./duration.js";
import type { EbmlElementHeader } from "./ebml.js";
import type {
  Issues,
  WebmSegment,
  WebmTrack,
  WebmTrackBitstreamFrameStats
} from "./types.js";

const describeTrackNumber = (track: WebmTrack): string => {
  if (track.trackNumber != null) return `#${track.trackNumber}`;
  return "(unknown number)";
};

const appendBitstreamFrameWarnings = (issues: Issues, tracks: WebmTrack[]): void => {
  for (const track of tracks) {
    const stats = track.bitstreamFrameStats;
    if (!stats || stats.parsedFrameCount === 0) continue;
    const declaredWidth = track.video?.pixelWidth ?? null;
    const declaredHeight = track.video?.pixelHeight ?? null;
    const trackLabel = describeTrackNumber(track);
    if ((stats.uniqueSizes?.length ?? 0) > 1) {
      const range =
        stats.minWidth != null &&
        stats.maxWidth != null &&
        stats.minHeight != null &&
        stats.maxHeight != null
          ? `${stats.minWidth}x${stats.minHeight}..${stats.maxWidth}x${stats.maxHeight}`
          : "unknown";
      issues.push(
        `Video track ${trackLabel} has variable VP8 keyframe sizes in bitstream ` +
        `(${stats.parsedFrameCount} parsed keyframes, ${stats.uniqueSizes.length} unique sizes, range ${range}).`
      );
    }
    if (stats.mismatchWithTrackEntryCount > 0) {
      const declared =
        declaredWidth != null && declaredHeight != null
          ? `${declaredWidth}x${declaredHeight}`
          : "unknown";
      issues.push(
        `Video track ${trackLabel} TrackEntry PixelWidth/PixelHeight (${declared}) differ from parsed ` +
        `VP8 keyframe size in ${stats.mismatchWithTrackEntryCount}/${stats.parsedFrameCount} keyframes.`
      );
    }
    if (
      stats.allBlocksAreKeyframes === true &&
      stats.blockCount > 1 &&
      (stats.uniqueSizes?.length ?? 0) > 1
    ) {
      issues.push(
        `Video track ${trackLabel} has all blocks marked as keyframes ` +
        `(${stats.keyframeCount}/${stats.blockCount}) while frame size varies.`
      );
    }
  }
};

export const enrichSegmentWithClusterScan = async (
  file: File,
  segmentHeader: EbmlElementHeader,
  segment: WebmSegment,
  issues: Issues
): Promise<void> => {
  const segmentSize = segment.dataSize ?? Math.max(0, file.size - segmentHeader.dataOffset);
  const timecodeScaleNs = segment.info?.timecodeScale ?? 1000000;
  const clusters = await scanSegmentForComputedDuration(
    file,
    segmentHeader,
    segmentSize,
    timecodeScaleNs,
    segment.tracks,
    issues
  );
  segment.clusterCount = clusters.clusterCount;
  segment.blockCount = clusters.blockCount;
  segment.keyframeCount = clusters.keyframeCount;
  segment.firstClusterOffset = clusters.firstClusterOffset;
  segment.computedDuration = clusters.computedDuration;
  const statsByTrack = new Map<number, WebmTrackBitstreamFrameStats>(
    clusters.trackFrameStats.map(stats => [stats.trackNumber, stats])
  );
  for (const track of segment.tracks) {
    if (track.trackNumber == null) continue;
    const stats = statsByTrack.get(track.trackNumber);
    if (stats) track.bitstreamFrameStats = stats;
  }
  appendBitstreamFrameWarnings(issues, segment.tracks);
};
