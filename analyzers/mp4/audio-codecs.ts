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

  if (cursor >= limit) {
    return {
      format,
      codecString: format,
      profile: null,
      level: null,
      description: null,
      width: null,
      height: null,
      pixelAspectRatio: null,
      channels: channelCount,
      sampleRate: sampleRateFromEntry,
      bitDepth: null,
      bitrate: null,
      aac: { audioObjectType, samplingFrequencyIndex, channelConfiguration }
    };
  }

  const tag = view.getUint8(cursor);
  if (tag !== 0x03) {
    return {
      format,
      codecString: format,
      profile: null,
      level: null,
      description: null,
      width: null,
      height: null,
      pixelAspectRatio: null,
      channels: channelCount,
      sampleRate: sampleRateFromEntry,
      bitDepth: null,
      bitrate: null,
      aac: { audioObjectType, samplingFrequencyIndex, channelConfiguration }
    };
  }
  const sizeField = readExpandableSize(view, cursor + 1, limit);
  if (!sizeField) {
    return {
      format,
      codecString: format,
      profile: null,
      level: null,
      description: null,
      width: null,
      height: null,
      pixelAspectRatio: null,
      channels: channelCount,
      sampleRate: sampleRateFromEntry,
      bitDepth: null,
      bitrate: null,
      aac: { audioObjectType, samplingFrequencyIndex, channelConfiguration }
    };
  }
  cursor += 1 + sizeField.length;
  cursor += 2;
  cursor += 1;
  if (cursor >= limit) {
    return {
      format,
      codecString: format,
      profile: null,
      level: null,
      description: null,
      width: null,
      height: null,
      pixelAspectRatio: null,
      channels: channelCount,
      sampleRate: sampleRateFromEntry,
      bitDepth: null,
      bitrate: null,
      aac: { audioObjectType, samplingFrequencyIndex, channelConfiguration }
    };
  }
  if (view.getUint8(cursor) === 0x04) {
    const dcdSize = readExpandableSize(view, cursor + 1, limit);
    if (dcdSize) {
      const dcdStart = cursor + 1 + dcdSize.length;
      if (dcdStart + dcdSize.size <= limit) {
        const objectTypeIndication = view.getUint8(dcdStart);
        codecString = `${format}.${objectTypeIndication.toString(16)}`;
        const streamTypeByte = view.getUint8(dcdStart + 1);
        const bufferSize =
          (view.getUint8(dcdStart + 2) << 16) |
          (view.getUint8(dcdStart + 3) << 8) |
          view.getUint8(dcdStart + 4);
        const maxBitrate = view.getUint32(dcdStart + 5, false);
        const avgBitrate = view.getUint32(dcdStart + 9, false);
        const streamType = (streamTypeByte >> 2) & 0x3f;
        description = `streamType ${streamType}, buffer ${bufferSize}, bitrate ${avgBitrate || maxBitrate || 0}`;
        const nextTag = dcdStart + 13;
        if (nextTag < limit && view.getUint8(nextTag) === 0x05) {
          const dsi = readExpandableSize(view, nextTag + 1, limit);
          if (dsi) {
            const asc = parseAudioSpecificConfig(view, nextTag + 1 + dsi.length, dsi.size);
            audioObjectType = asc.audioObjectType;
            samplingFrequencyIndex = asc.samplingFrequencyIndex;
            channelConfiguration = asc.channelConfiguration;
            codecString = `${format}.40.${audioObjectType ?? objectTypeIndication}`;
          }
        }
      }
    }
  }
  const sampleRate: number | null =
    samplingFrequencyIndex != null && samplingFrequencyIndex < AAC_SAMPLE_RATES.length
      ? AAC_SAMPLE_RATES[samplingFrequencyIndex] ?? null
      : sampleRateFromEntry;
  const channels: number | null =
    channelConfiguration != null && channelConfiguration > 0 ? channelConfiguration : channelCount;
  return {
    format,
    codecString: codecString ?? format,
    profile: null,
    level: null,
    description,
    width: null,
    height: null,
    pixelAspectRatio: null,
    channels,
    sampleRate,
    bitDepth: null,
    bitrate: null,
    aac: { audioObjectType, samplingFrequencyIndex, channelConfiguration }
  };
};
