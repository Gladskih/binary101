"use strict";

import { parseMetadataBlock } from "./metadata-blocks.js";
import type { FlacMetadataBlockDetail, FlacParseResult, FlacStreamInfo } from "./types.js";

const FLAC_SIGNATURE = 0x664c6143;
const MAX_BLOCKS = 128;

const readRange = async (file: File, offset: number, length: number): Promise<DataView> =>
  new DataView(await file.slice(offset, offset + length).arrayBuffer());

const computeAverageBitrate = (
  audioBytes: number | null,
  durationSeconds: number | null
): number | null => {
  if (!audioBytes || !durationSeconds || durationSeconds <= 0) return null;
  const kbps = Math.round((audioBytes * 8) / (durationSeconds * 1000));
  return Number.isFinite(kbps) ? kbps : null;
};

const parseFlac = async (file: File): Promise<FlacParseResult | null> => {
  if (file.size < 4) return null;
  const signatureView = await readRange(file, 0, 4);
  if (signatureView.getUint32(0, false) !== FLAC_SIGNATURE) return null;

  const warnings: string[] = [];
  const blocks: FlacMetadataBlockDetail[] = [];
  let offset = 4;
  let audioDataOffset: number | null = null;
  let streamInfo: FlacStreamInfo | null = null;

  for (let blockIndex = 0; blockIndex < MAX_BLOCKS && offset + 4 <= file.size; blockIndex += 1) {
    const header = await readRange(file, offset, 4);
    const headerByte = header.getUint8(0);
    const isLast = (headerByte & 0x80) !== 0;
    const rawType = headerByte & 0x7f;
    const length = (header.getUint8(1) << 16) | (header.getUint8(2) << 8) | header.getUint8(3);
    const dataOffset = offset + 4;
    const remaining = Math.max(0, file.size - dataOffset);
    const truncated = remaining < length;
    const dataLength = Math.min(length, remaining);
    const data =
      dataLength > 0
        ? await readRange(file, dataOffset, dataLength)
        : new DataView(new ArrayBuffer(0));

    const block = parseMetadataBlock(rawType, isLast, length, offset, data, truncated, warnings);
    blocks.push(block);
    if (block.type === "STREAMINFO" && block.info) streamInfo = block.info;

    offset = dataOffset + length;
    if (isLast) {
      audioDataOffset = dataOffset + length;
      break;
    }
    if (length === 0) {
      warnings.push("Metadata block with zero length; stopping to avoid infinite loop.");
      audioDataOffset = dataOffset;
      break;
    }
  }

  if (audioDataOffset == null) {
    warnings.push("No metadata block marked as last; audio start offset is approximate.");
    audioDataOffset = Math.min(Math.max(offset, 4), file.size);
  }

  const audioDataBytes =
    audioDataOffset <= file.size ? Math.max(0, file.size - audioDataOffset) : null;
  if (streamInfo && audioDataBytes != null) {
    streamInfo.averageBitrateKbps = computeAverageBitrate(
      audioDataBytes,
      streamInfo.durationSeconds
    );
  }
  if (!streamInfo) warnings.push("STREAMINFO block is missing.");

  return { isFlac: true, streamInfo, blocks, audioDataOffset, audioDataBytes, warnings };
};

export { parseFlac };
