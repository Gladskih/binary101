"use strict";

export const nowIsoString = (): string => new Date().toISOString();

export const formatHumanSize = (byteCount: number): string => {
  const base = 1024;
  const units = ["B", "KB", "MB", "GB", "TB"];
  let unitIndex = 0;
  let value = byteCount;
  while (value >= base && unitIndex < units.length - 1) {
    value /= base;
    unitIndex += 1;
  }
  const roundedValue = value >= 100 ? Math.round(value) : Math.round(value * 10) / 10;
  return `${roundedValue} ${units[unitIndex]} (${byteCount} bytes)`;
};

export const toHex32 = (value: number, width = 0): string => {
  const masked = Number(value >>> 0);
  return "0x" + masked.toString(16).padStart(width, "0");
};

export const toHex64 = (value: bigint | number): string => "0x" + value.toString(16);

export const formatUnixSecondsOrDash = (unixSeconds: number): string => {
  if (!Number.isFinite(unixSeconds) || unixSeconds <= 0) return "-";
  const date = new Date(unixSeconds * 1000);
  const year = date.getUTCFullYear();
  const iso = date.toISOString();
  return year < 1990 || year > 2100 ? `${iso} (unusual)` : iso;
};

export const readAsciiString = (dataView: DataView, offset: number, maxLength: number): string => {
  let result = "";
  for (let index = 0; index < maxLength && offset + index < dataView.byteLength; index += 1) {
    const codePoint = dataView.getUint8(offset + index);
    if (codePoint === 0) break;
    result += String.fromCharCode(codePoint);
  }
  return result;
};

export const isPrintableByte = (byteValue: number): boolean =>
  byteValue >= 0x20 && byteValue <= 0x7e;

export const collectPrintableRuns = (
  bytes: Uint8Array | number[],
  minimumLength: number
): string[] => {
  const runs: string[] = [];
  let current = "";
  for (const byteValue of bytes) {
    if (isPrintableByte(byteValue)) {
      current += String.fromCharCode(byteValue);
      if (current.length > 4096) {
        runs.push(current);
        current = "";
      }
    } else if (current.length >= minimumLength) {
      runs.push(current);
      current = "";
    } else {
      current = "";
    }
  }
  if (current.length >= minimumLength) runs.push(current);
  return runs;
};

export const bufferToHex = (arrayBuffer: ArrayBuffer | ArrayBufferView): string =>
  [...new Uint8Array(arrayBuffer as ArrayBufferLike)]
    .map(byteValue => byteValue.toString(16).padStart(2, "0"))
    .join("");

export const alignUpTo = (value: number, alignment: number): number => {
  if (!alignment) return value >>> 0;
  const mask = (alignment - 1) >>> 0;
  return ((value + mask) & ~mask) >>> 0;
};

// Backwards-compatible aliases kept while refactoring callers.
export const nowIso = nowIsoString;
export const humanSize = formatHumanSize;
export const hex = toHex32;
export const hex64 = toHex64;
export const isoOrDash = formatUnixSecondsOrDash;
export const ascii = readAsciiString;
export const printable = isPrintableByte;
export const runStrings = collectPrintableRuns;
export const bufToHex = bufferToHex;
export const alignUp = alignUpTo;
