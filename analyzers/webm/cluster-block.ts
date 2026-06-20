"use strict";

import { MAX_EBML_VINT_BYTES } from "./constants.js";
import { readVint } from "./ebml.js";
import type { Issues } from "./types.js";

export type OnClusterBlock = (timing: {
  trackNumber: number | null;
  timecode: number | null;
  durationTimecode: number | null;
  frames: number;
  isKeyframe: boolean;
  lacingMode: number | null;
  payload: Uint8Array | null;
}) => void;

export type WebmBlockHeader = {
  trackNumber: number | null;
  relativeTimecode: number | null;
  flags: number | null;
  frames: number;
  lacingMode: number | null;
  payloadOffset: number | null;
};

// Matroska Block structure and flags:
// https://www.matroska.org/technical/notes.html#block-structure
const BLOCK_TIMECODE_BYTES = 2;
const BLOCK_FLAGS_BYTES = Uint8Array.BYTES_PER_ELEMENT;
const DEFAULT_BLOCK_FRAME_COUNT = 1;
export const MIN_BLOCK_HEADER_BYTES =
  Uint8Array.BYTES_PER_ELEMENT + BLOCK_TIMECODE_BYTES + BLOCK_FLAGS_BYTES;
export const WEBM_BLOCK_FLAGS = {
  lacingMask: 0x06,
  lacingShift: 1,
  keyframe: 0x80
} as const;
// RFC 6386 section 9.1 defines the ten-byte uncompressed VP8 keyframe header.
export const VP8_KEYFRAME_HEADER_BYTES = 10;
export const BLOCK_ANALYSIS_PREFIX_BYTES =
  MAX_EBML_VINT_BYTES +
  BLOCK_TIMECODE_BYTES +
  BLOCK_FLAGS_BYTES +
  Uint8Array.BYTES_PER_ELEMENT +
  VP8_KEYFRAME_HEADER_BYTES;

const emptyBlockHeader = (): WebmBlockHeader => ({
  trackNumber: null,
  relativeTimecode: null,
  flags: null,
  frames: DEFAULT_BLOCK_FRAME_COUNT,
  lacingMode: null,
  payloadOffset: null
});

export const parseStreamBlockHeader = (
  data: Uint8Array,
  issues: Issues
): WebmBlockHeader => {
  if (data.byteLength < MIN_BLOCK_HEADER_BYTES) return emptyBlockHeader();
  const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
  const trackVint = readVint(view, 0);
  if (!trackVint) return emptyBlockHeader();
  const trackNumber =
    trackVint.data <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(trackVint.data) : null;
  if (trackNumber == null) issues.push("Block track number exceeds safe integer range.");
  const timecodeOffset = trackVint.length;
  if (timecodeOffset + BLOCK_TIMECODE_BYTES > data.byteLength) {
    issues.push("Block timecode is truncated.");
    return { ...emptyBlockHeader(), trackNumber };
  }
  const relativeTimecode = view.getInt16(timecodeOffset, false);
  const flagsOffset = timecodeOffset + BLOCK_TIMECODE_BYTES;
  if (flagsOffset >= data.byteLength) {
    issues.push("Block flags are truncated.");
    return { ...emptyBlockHeader(), trackNumber, relativeTimecode };
  }
  const flags = view.getUint8(flagsOffset);
  const lacingMode =
    (flags & WEBM_BLOCK_FLAGS.lacingMask) >> WEBM_BLOCK_FLAGS.lacingShift;
  if (lacingMode === 0) {
    return {
      trackNumber,
      relativeTimecode,
      flags,
      frames: DEFAULT_BLOCK_FRAME_COUNT,
      lacingMode,
      payloadOffset: flagsOffset + BLOCK_FLAGS_BYTES
    };
  }
  const laceCountOffset = flagsOffset + BLOCK_FLAGS_BYTES;
  if (laceCountOffset >= data.byteLength) issues.push("Block lacing header is truncated.");
  return {
    trackNumber,
    relativeTimecode,
    flags,
    frames: laceCountOffset < data.byteLength
      ? view.getUint8(laceCountOffset) + DEFAULT_BLOCK_FRAME_COUNT
      : DEFAULT_BLOCK_FRAME_COUNT,
    lacingMode,
    payloadOffset: null
  };
};

const blockPayloadPrefix = (
  data: Uint8Array,
  block: WebmBlockHeader
): Uint8Array | null => {
  if (block.payloadOffset == null || block.payloadOffset >= data.byteLength) return null;
  return data.subarray(
    block.payloadOffset,
    Math.min(data.byteLength, block.payloadOffset + VP8_KEYFRAME_HEADER_BYTES)
  );
};

export const emitStreamBlockTiming = (
  block: WebmBlockHeader,
  data: Uint8Array,
  clusterTimecode: number | null,
  durationTimecode: number | null,
  isKeyframe: boolean,
  onBlock: OnClusterBlock
): void => {
  if (block.trackNumber == null || block.relativeTimecode == null) return;
  onBlock({
    trackNumber: block.trackNumber,
    timecode: (clusterTimecode ?? 0) + block.relativeTimecode,
    durationTimecode,
    frames: block.frames,
    isKeyframe,
    lacingMode: block.lacingMode,
    payload: blockPayloadPrefix(data, block)
  });
};
