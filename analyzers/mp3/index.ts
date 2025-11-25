"use strict";

import { ID3V1_SIZE } from "./constants.js";
import { parseId3v1, parseId3v2 } from "./id3.js";
import {
  estimateDuration,
  findFirstFrame,
  parseFrameHeader,
  parseVbrHeader,
  validateNextFrame
} from "./mpeg.js";
import { parseApeTag, parseLyrics3 } from "./tags.js";
import type {
  ApeTag,
  Id3v1Tag,
  Id3v2Tag,
  Lyrics3Tag,
  Mp3Summary,
  Mp3FailureResult,
  Mp3ParseResult,
  Mp3SuccessResult,
  MpegFrameHeader,
  VbrHeader
} from "./types.js";

function computeTrailingStart(
  fileSize: number,
  id3v1: Id3v1Tag | null,
  apeTag: ApeTag | null,
  lyrics3: Lyrics3Tag | null
): number {
  let trailingStart = fileSize;
  if (id3v1) trailingStart = Math.min(trailingStart, fileSize - ID3V1_SIZE);
  if (apeTag && Number.isFinite(apeTag.offset)) {
    trailingStart = Math.min(trailingStart, Math.max(0, apeTag.offset));
  }
  if (lyrics3 && typeof lyrics3.offset === "number" && Number.isFinite(lyrics3.offset)) {
    trailingStart = Math.min(trailingStart, Math.max(0, lyrics3.offset));
  }
  return trailingStart;
}

function computeAverageBitrate(
  audioBytes: number,
  durationSeconds: number | null,
  frameBitrate: number | null
): number | null {
  if (durationSeconds && durationSeconds > 0 && audioBytes > 0) {
    return Math.round((audioBytes * 8) / (durationSeconds * 1000));
  }
  return frameBitrate || null;
}

function detectMultipleId3(id3v2: Id3v2Tag | null, dv: DataView, issues: string[]): void {
  if (!id3v2) return;
  const nextOffset = id3v2.tagTotalSize;
  if (nextOffset + 3 <= dv.byteLength) {
    const b0 = dv.getUint8(nextOffset);
    const b1 = dv.getUint8(nextOffset + 1);
    const b2 = dv.getUint8(nextOffset + 2);
    if (b0 === 0x49 && b1 === 0x44 && b2 === 0x33) {
      issues.push("Multiple ID3v2 tags detected.");
    }
  }
}

function findFirstFrameWithFallback(
  dv: DataView,
  audioStart: number,
  id3v2: Id3v2Tag | null,
  issues: string[]
): MpegFrameHeader | null {
  const primary = findFirstFrame(dv, audioStart, issues) as MpegFrameHeader | null;
  if (primary || !id3v2) return primary;

  if (audioStart < 0 || audioStart > dv.byteLength) {
    issues.push(
      "ID3v2 tag size is inconsistent with file length; scanning whole file for MPEG frame header."
    );
  } else {
    issues.push(
      "ID3v2 tag present but no MPEG frame at declared audio start; scanning whole file instead."
    );
  }

  const limit = Math.max(0, dv.byteLength - 4);
  for (let offset = 0; offset <= limit; offset += 1) {
    const frame = parseFrameHeader(dv, offset);
    if (frame) {
      return frame;
    }
  }
  return null;
}

export function probeMp3(dv: DataView): boolean {
  if (dv.byteLength < 3) return false;
  if (dv.getUint8(0) === 0x49 && dv.getUint8(1) === 0x44 && dv.getUint8(2) === 0x33) {
    return true;
  }
  const scanLimit = Math.min(dv.byteLength - 4, 65536);
  for (let offset = 0; offset <= scanLimit; offset += 1) {
    if (parseFrameHeader(dv, offset)) return true;
  }
  return false;
}

export async function parseMp3(file: File): Promise<Mp3ParseResult> {
  const buffer = await file.arrayBuffer();
  const dv = new DataView(buffer);
  const issues: string[] = [];
  const id3v2 = parseId3v2(dv, issues) as Id3v2Tag | null;
  detectMultipleId3(id3v2, dv, issues);
  const id3v1 = parseId3v1(dv) as Id3v1Tag | null;
  const apeTag = parseApeTag(dv, issues) as ApeTag | null;
  const lyrics3 = parseLyrics3(dv, issues) as Lyrics3Tag | null;

  const audioStart = id3v2 ? id3v2.tagTotalSize : 0;
  const firstFrame = findFirstFrameWithFallback(dv, audioStart, id3v2, issues);
  if (!firstFrame) {
    const reason = id3v2
      ? "ID3v2 tag present but no valid MPEG frame header found."
      : "no ID3v2 tag and no valid MPEG frame header";
    const failure: Mp3FailureResult = {
      isMp3: false,
      mimeGuess: null,
      reason,
      id3v2,
      id3v1,
      apeTag,
      lyrics3,
      warnings: issues
    };
    return failure;
  }

  if (!firstFrame.frameLengthBytes) {
    issues.push("MPEG frame length could not be computed from header fields.");
  }
  const secondFrameValidated = validateNextFrame(dv, firstFrame, issues);
  const vbr = parseVbrHeader(dv, firstFrame) as VbrHeader | null;
  const trailingStart = computeTrailingStart(dv.byteLength, id3v1, apeTag, lyrics3);
  const audioDataOffset = firstFrame.offset;
  const audioDataBytes = Math.max(0, trailingStart - audioDataOffset);
  const nonAudioBytes = audioDataOffset + Math.max(0, dv.byteLength - trailingStart);
  const durationSeconds = estimateDuration(firstFrame, vbr, audioDataBytes, issues);
  const bitrateKbps = computeAverageBitrate(audioDataBytes, durationSeconds, firstFrame.bitrateKbps);
  const isVbr = Boolean(vbr && vbr.vbrDetected);

  const summary = {
    hasId3v2: Boolean(id3v2),
    hasId3v1: Boolean(id3v1),
    hasApeTag: Boolean(apeTag),
    hasLyrics3: Boolean(lyrics3),
    audioDataOffset,
    durationSeconds,
    bitrateKbps,
    channelMode: firstFrame.channelMode,
    sampleRateHz: firstFrame.sampleRate,
    mpegVersion: firstFrame.versionLabel,
    layer: firstFrame.layerLabel,
    isVbr,
    warnings: issues
  } satisfies Mp3Summary;

  const success: Mp3SuccessResult = {
    isMp3: true,
    mimeGuess: "audio/mpeg",
    summary,
    id3v2,
    id3v1,
    apeTag,
    lyrics3,
    mpeg: {
      firstFrame,
      secondFrameValidated,
      nonAudioBytes
    },
    vbr,
    durationSeconds,
    bitrateKbps,
    audioDataBytes,
    warnings: issues
  };
  return success;
}
