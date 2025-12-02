"use strict";

export type BoxHeader = {
  type: string;
  size: number;
  start: number;
  end: number;
  headerSize: number;
  dataOffset: number;
  largesize?: number | null;
  truncated?: boolean;
};

const MP4_EPOCH_MS = Date.UTC(1904, 0, 1);

export const toFourCcFromView = (view: DataView, offset: number): string => {
  if (offset + 4 > view.byteLength) return "";
  return String.fromCharCode(
    view.getUint8(offset),
    view.getUint8(offset + 1),
    view.getUint8(offset + 2),
    view.getUint8(offset + 3)
  );
};

export const readUint16Safe = (view: DataView, offset: number): number | null =>
  offset + 2 <= view.byteLength ? view.getUint16(offset, false) : null;

export const readFixed1616 = (value: number): number => Math.round((value / 65536) * 1000) / 1000;
export const readFixed88 = (value: number): number => Math.round((value / 256) * 1000) / 1000;

export const readBoxHeaderFromFile = async (
  file: File,
  offset: number,
  issues: string[],
  context: string
): Promise<BoxHeader | null> => {
  if (offset + 8 > file.size) {
    issues.push(`${context}: not enough data for box header at ${offset}.`);
    return null;
  }
  const headerBuffer = await file.slice(offset, offset + 16).arrayBuffer();
  const dv = new DataView(headerBuffer);
  const size = dv.getUint32(0, false);
  const type = toFourCcFromView(dv, 4);
  let headerSize = 8;
  let largesize: number | null = null;
  if (size === 1) {
    const large = dv.getBigUint64(8, false);
    largesize = Number(large);
    headerSize = 16;
  }
  const boxSize = size === 0 ? file.size - offset : size === 1 ? largesize ?? 0 : size;
  if (!Number.isFinite(boxSize) || boxSize < headerSize) {
    issues.push(`${context}: invalid size for ${type || "unknown"} at ${offset}.`);
    return null;
  }
  const end = Math.min(file.size, offset + boxSize);
  const truncated = offset + boxSize > file.size;
  return {
    type,
    size: boxSize,
    start: offset,
    end,
    headerSize,
    dataOffset: offset + headerSize,
    largesize,
    truncated
  };
};

export const readBoxHeaderFromView = (
  view: DataView,
  relativeOffset: number,
  absoluteStart: number,
  issues: string[] | null
): BoxHeader | null => {
  if (relativeOffset + 8 > view.byteLength) {
    if (issues) issues.push(`Box header truncated at ${absoluteStart + relativeOffset}.`);
    return null;
  }
  const size = view.getUint32(relativeOffset, false);
  const type = toFourCcFromView(view, relativeOffset + 4);
  let headerSize = 8;
  let largesize: number | null = null;
  if (size === 1) {
    if (relativeOffset + 16 > view.byteLength) {
      if (issues) issues.push(`Large size header truncated for ${type} at ${absoluteStart + relativeOffset}.`);
      return null;
    }
    const large = view.getBigUint64(relativeOffset + 8, false);
    largesize = Number(large);
    headerSize = 16;
  }
  const boxSize = size === 0 ? view.byteLength - relativeOffset : size === 1 ? largesize ?? 0 : size;
  if (!Number.isFinite(boxSize) || boxSize < headerSize) {
    if (issues) issues.push(`Invalid size for ${type || "unknown"} at ${absoluteStart + relativeOffset}.`);
    return null;
  }
  const end = Math.min(view.byteLength, relativeOffset + boxSize);
  const truncated = relativeOffset + boxSize > view.byteLength;
  return {
    type,
    size: boxSize,
    start: absoluteStart + relativeOffset,
    end: absoluteStart + end,
    headerSize,
    dataOffset: absoluteStart + relativeOffset + headerSize,
    largesize,
    truncated
  };
};

export const parseLanguage = (value: number | null): string | null => {
  if (value == null) return null;
  const c1 = ((value >> 10) & 0x1f) + 0x60;
  const c2 = ((value >> 5) & 0x1f) + 0x60;
  const c3 = (value & 0x1f) + 0x60;
  if (c1 < 0x61 || c2 < 0x61 || c3 < 0x61) return null;
  return String.fromCharCode(c1, c2, c3);
};

export const parseCreationTime = (seconds: number | null): string | null => {
  if (seconds == null || Number.isNaN(seconds)) return null;
  const millis = seconds * 1000;
  const timestamp = MP4_EPOCH_MS + millis;
  if (!Number.isFinite(timestamp) || timestamp < 0) return null;
  return new Date(timestamp).toISOString();
};
