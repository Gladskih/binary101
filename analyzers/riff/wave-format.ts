"use strict";

const WAVE_FORMAT_NAMES: Record<number, string> = {
  0x0001: "PCM (uncompressed)",
  0x0003: "IEEE float",
  0x0006: "A-law",
  0x0007: "Mu-law",
  0x0011: "IMA ADPCM",
  0x0050: "MPEG Layer 1/2",
  0x00ff: "AAC",
  0x0161: "Windows Media Audio",
  0x0162: "Windows Media Audio Professional",
  0x0163: "Windows Media Audio Lossless",
  0x2000: "AC-3",
  0xfffe: "WAVE_FORMAT_EXTENSIBLE"
};

export interface WaveFormatInfo {
  audioFormat: number;
  formatName: string | null;
  channels: number | null;
  sampleRate: number | null;
  byteRate: number | null;
  blockAlign: number | null;
  bitsPerSample: number | null;
  cbSize: number | null;
  validBitsPerSample: number | null;
  channelMask: number | null;
  subFormat: string | null;
  isExtensible: boolean;
}

const readGuid = (dv: DataView, offset: number): string => {
  const toHex = (value: number, width: number) => value.toString(16).padStart(width, "0");
  const data1 = dv.getUint32(offset, true);
  const data2 = dv.getUint16(offset + 4, true);
  const data3 = dv.getUint16(offset + 6, true);
  let data4First = "";
  let data4Second = "";
  for (let i = 0; i < 2; i += 1) {
    data4First += toHex(dv.getUint8(offset + 8 + i), 2);
  }
  for (let i = 2; i < 8; i += 1) {
    data4Second += toHex(dv.getUint8(offset + 8 + i), 2);
  }
  return `${toHex(data1, 8)}-${toHex(data2, 4)}-${toHex(data3, 4)}-${data4First}-${data4Second}`;
};

export const describeWaveFormatTag = (formatTag: number | null): string | null => {
  if (formatTag == null) return null;
  return WAVE_FORMAT_NAMES[formatTag] || null;
};

export const parseWaveFormat = (
  dv: DataView,
  offset: number,
  size: number,
  littleEndian: boolean,
  issues: string[]
): WaveFormatInfo | null => {
  const minimumHeader = 16;
  if (size < minimumHeader || offset + minimumHeader > dv.byteLength) {
    issues.push("fmt chunk is truncated or smaller than the 16-byte WAVEFORMAT header.");
    return null;
  }
  const read16 = (fieldOffset: number) => dv.getUint16(offset + fieldOffset, littleEndian);
  const read32 = (fieldOffset: number) => dv.getUint32(offset + fieldOffset, littleEndian);
  const audioFormat = read16(0);
  const channels = read16(2);
  const sampleRate = read32(4);
  const byteRate = read32(8);
  const blockAlign = read16(12);
  const bitsPerSample = read16(14);

  let cbSize: number | null = null;
  let validBitsPerSample: number | null = null;
  let channelMask: number | null = null;
  let subFormat: string | null = null;
  if (size >= 18 && offset + 18 <= dv.byteLength) {
    cbSize = read16(16);
    const hasExtensibleFields = audioFormat === 0xfffe && size >= 40 && cbSize >= 22;
    if (hasExtensibleFields && offset + 40 <= dv.byteLength) {
      validBitsPerSample = read16(18);
      channelMask = read32(20);
      subFormat = readGuid(dv, offset + 24);
    } else if (audioFormat === 0xfffe) {
      issues.push("WAVE_FORMAT_EXTENSIBLE detected but extension fields are truncated.");
    }
  }

  return {
    audioFormat,
    formatName: describeWaveFormatTag(audioFormat),
    channels,
    sampleRate,
    byteRate,
    blockAlign,
    bitsPerSample,
    cbSize,
    validBitsPerSample,
    channelMask,
    subFormat,
    isExtensible: audioFormat === 0xfffe
  };
};
