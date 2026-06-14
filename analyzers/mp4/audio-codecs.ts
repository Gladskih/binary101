"use strict";

import type { Mp4CodecDetails } from "./types.js";

const AAC_SAMPLE_RATES = [
  96000, 88200, 64000, 48000, 44100, 32000, 24000, 22050, 16000, 12000, 11025, 8000, 7350
];

const readExpandableSize = (view: DataView, offset: number, limit: number): { size: number; length: number } | null => {
  let size = 0;
  let consumed = 0;
  while (consumed < 4 && offset + consumed < limit) {
    const b = view.getUint8(offset + consumed);
    size = (size << 7) | (b & 0x7f);
    consumed += 1;
    if ((b & 0x80) === 0) return { size, length: consumed };
  }
  return null;
};

const parseAudioSpecificConfig = (view: DataView, offset: number, length: number) => {
  if (length < 2) return { audioObjectType: null, samplingFrequencyIndex: null, channelConfiguration: null };
  const b0 = view.getUint8(offset);
  const b1 = view.getUint8(offset + 1);
  const audioObjectType = b0 >> 3;
  const samplingFrequencyIndex = ((b0 & 0x07) << 1) | (b1 >> 7);
  const channelConfiguration = (b1 >> 3) & 0x0f;
  return { audioObjectType, samplingFrequencyIndex, channelConfiguration };
};

const createAudioCodecDetails = (
  format: string,
  sampleRate: number | null,
  channelCount: number | null,
  description: string | null,
  codecString: string | null,
  audioObjectType: number | null,
  samplingFrequencyIndex: number | null,
  channelConfiguration: number | null
): Mp4CodecDetails => ({
  format,
  codecString: codecString ?? format,
  profile: null,
  level: null,
  description,
  width: null,
  height: null,
  pixelAspectRatio: null,
  channels: channelConfiguration != null && channelConfiguration > 0 ? channelConfiguration : channelCount,
  sampleRate:
    samplingFrequencyIndex != null && samplingFrequencyIndex < AAC_SAMPLE_RATES.length
      ? AAC_SAMPLE_RATES[samplingFrequencyIndex] ?? null
      : sampleRate,
  bitDepth: null,
  bitrate: null,
  aac: { audioObjectType, samplingFrequencyIndex, channelConfiguration }
});

const parseDecoderSpecificInfo = (
  view: DataView,
  nextTag: number,
  limit: number
): ReturnType<typeof parseAudioSpecificConfig> | null => {
  if (nextTag >= limit || view.getUint8(nextTag) !== 0x05) return null;
  const dsi = readExpandableSize(view, nextTag + 1, limit);
  if (!dsi || nextTag + 1 + dsi.length + dsi.size > limit) return null;
  return parseAudioSpecificConfig(view, nextTag + 1 + dsi.length, dsi.size);
};

const parseDecoderConfig = (
  view: DataView,
  cursor: number,
  limit: number,
  format: string
) => {
  const dcdSize = readExpandableSize(view, cursor + 1, limit);
  if (!dcdSize) return null;
  const dcdStart = cursor + 1 + dcdSize.length;
  if (dcdStart + dcdSize.size > limit || dcdStart + 13 > limit) return null;
  const objectTypeIndication = view.getUint8(dcdStart);
  const streamTypeByte = view.getUint8(dcdStart + 1);
  const bufferSize =
    (view.getUint8(dcdStart + 2) << 16) |
    (view.getUint8(dcdStart + 3) << 8) |
    view.getUint8(dcdStart + 4);
  const maxBitrate = view.getUint32(dcdStart + 5, false);
  const avgBitrate = view.getUint32(dcdStart + 9, false);
  const streamType = (streamTypeByte >> 2) & 0x3f;
  const asc = parseDecoderSpecificInfo(view, dcdStart + 13, limit);
  return {
    codecString: asc ? `${format}.40.${asc.audioObjectType ?? objectTypeIndication}` : `${format}.${objectTypeIndication.toString(16)}`,
    description: `streamType ${streamType}, buffer ${bufferSize}, bitrate ${avgBitrate || maxBitrate || 0}`,
    audioObjectType: asc?.audioObjectType ?? null,
    samplingFrequencyIndex: asc?.samplingFrequencyIndex ?? null,
    channelConfiguration: asc?.channelConfiguration ?? null
  };
};

export const readEsds = (
  view: DataView,
  start: number,
  size: number,
  format: string,
  sampleRateFromEntry: number | null,
  channelCount: number | null
): Mp4CodecDetails => {
  const limit = start + size;
  let cursor = start + 4;
  let codecString: string | null = null;
  let description: string | null = null;
  let audioObjectType: number | null = null;
  let samplingFrequencyIndex: number | null = null;
  let channelConfiguration: number | null = null;
  const createCurrentDetails = (): Mp4CodecDetails =>
    createAudioCodecDetails(
      format,
      sampleRateFromEntry,
      channelCount,
      description,
      codecString,
      audioObjectType,
      samplingFrequencyIndex,
      channelConfiguration
    );

  if (cursor >= limit) {
    return createCurrentDetails();
  }

  const tag = view.getUint8(cursor);
  if (tag !== 0x03) {
    return createCurrentDetails();
  }
  const sizeField = readExpandableSize(view, cursor + 1, limit);
  if (!sizeField) {
    return createCurrentDetails();
  }
  cursor += 1 + sizeField.length;
  cursor += 2;
  cursor += 1;
  if (cursor >= limit) {
    return createCurrentDetails();
  }
  if (view.getUint8(cursor) === 0x04) {
    const decoderConfig = parseDecoderConfig(view, cursor, limit, format);
    if (decoderConfig) {
      codecString = decoderConfig.codecString;
      description = decoderConfig.description;
      audioObjectType = decoderConfig.audioObjectType;
      samplingFrequencyIndex = decoderConfig.samplingFrequencyIndex;
      channelConfiguration = decoderConfig.channelConfiguration;
    }
  }
  return createCurrentDetails();
};
