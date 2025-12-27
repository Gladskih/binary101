"use strict";
import type { ProbeResult } from "./probe-types.js";

const detectPng = (dv: DataView): ProbeResult => {
  if (dv.byteLength < 8) return null;
  const sig0 = dv.getUint32(0, false);
  const sig1 = dv.getUint32(4, false);
  return sig0 === 0x89504e47 && sig1 === 0x0d0a1a0a ? "PNG image" : null;
};

const detectJpeg = (dv: DataView): ProbeResult => {
  if (dv.byteLength < 4) return null;
  const marker = dv.getUint16(0, false);
  if (marker !== 0xffd8) return null;
  const jfif = dv.byteLength >= 11 && dv.getUint32(2, false) === 0x4a464946; // "JFIF"
  const exif = dv.byteLength >= 11 && dv.getUint32(2, false) === 0x45786966; // "Exif"
  if (jfif) return "JPEG image (JFIF)";
  if (exif) return "JPEG image (EXIF)";
  return "JPEG image";
};

const detectGif = (dv: DataView): ProbeResult => {
  if (dv.byteLength < 6) return null;
  const sig =
    String.fromCharCode(dv.getUint8(0)) +
    String.fromCharCode(dv.getUint8(1)) +
    String.fromCharCode(dv.getUint8(2)) +
    String.fromCharCode(dv.getUint8(3)) +
    String.fromCharCode(dv.getUint8(4)) +
    String.fromCharCode(dv.getUint8(5));
  if (sig === "GIF87a" || sig === "GIF89a") return "GIF image";
  return null;
};

const detectBmp = (dv: DataView): ProbeResult => {
  if (dv.byteLength < 2) return null;
  const sig = dv.getUint16(0, false);
  return sig === 0x424d ? "BMP bitmap image" : null;
};

const detectTiff = (dv: DataView): ProbeResult => {
  if (dv.byteLength < 4) return null;
  const sig = dv.getUint32(0, false);
  if (sig === 0x49492a00 || sig === 0x4d4d002a) return "TIFF image";
  return null;
};

const detectWebp = (dv: DataView): ProbeResult => {
  if (dv.byteLength < 12) return null;
  const riff = dv.getUint32(0, false);
  const webp = dv.getUint32(8, false);
  return riff === 0x52494646 && webp === 0x57454250 ? "WebP image" : null;
};

const detectIco = (dv: DataView): ProbeResult => {
  if (dv.byteLength < 6) return null;
  const reserved = dv.getUint16(0, true);
  const type = dv.getUint16(2, true);
  const count = dv.getUint16(4, true);
  if (reserved !== 0 || (type !== 1 && type !== 2) || count === 0) return null;

  const directoryBytes = 6 + count * 16;
  if (directoryBytes > dv.byteLength) return null;

  const firstEntryOffset = 6;
  const entryReserved = dv.getUint8(firstEntryOffset + 3);
  const bytesInRes = dv.getUint32(firstEntryOffset + 8, true);
  const imageOffset = dv.getUint32(firstEntryOffset + 12, true);
  if (entryReserved !== 0 || bytesInRes === 0) return null;
  if (imageOffset < directoryBytes || imageOffset >= dv.byteLength) return null;
  if (imageOffset + bytesInRes > dv.byteLength) return null;

  return "ICO/CUR icon image";
};

const detectAni = (dv: DataView): ProbeResult => {
  if (dv.byteLength < 12) return null;
  const riff = dv.getUint32(0, false);
  const acon = dv.getUint32(8, false);
  if (riff === 0x52494646 && acon === 0x41434f4e) return "Windows animated cursor (ANI)";
  return null;
};

const imageProbes: Array<(dv: DataView) => ProbeResult> = [
  detectPng,
  detectJpeg,
  detectGif,
  detectBmp,
  detectTiff,
  detectWebp,
  detectIco,
  detectAni
];

export { imageProbes };
