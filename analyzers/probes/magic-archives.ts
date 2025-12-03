"use strict";
import type { ProbeResult } from "./probe-types.js";

const detectZip = (dv: DataView): ProbeResult => {
  if (dv.byteLength < 4) return null;
  const sig = dv.getUint32(0, true);
  return sig === 0x04034b50 ? "ZIP archive (PK-based, e.g. Office, JAR, APK)" : null;
};

const detectGzip = (dv: DataView): ProbeResult => {
  if (dv.byteLength < 2) return null;
  const sig = dv.getUint16(0, true);
  return sig === 0x8b1f ? "gzip compressed data" : null;
};

const detectBzip2 = (dv: DataView): ProbeResult => {
  if (dv.byteLength < 3) return null;
  const b0 = dv.getUint8(0);
  const b1 = dv.getUint8(1);
  const b2 = dv.getUint8(2);
  return b0 === 0x42 && b1 === 0x5a && b2 === 0x68 ? "bzip2 compressed data" : null;
};

const detectSevenZip = (dv: DataView): ProbeResult => {
  if (dv.byteLength < 6) return null;
  const b0 = dv.getUint8(0);
  const b1 = dv.getUint8(1);
  const b2 = dv.getUint8(2);
  const b3 = dv.getUint8(3);
  const b4 = dv.getUint8(4);
  const b5 = dv.getUint8(5);
  if (
    b0 === 0x37 &&
    b1 === 0x7a &&
    b2 === 0xbc &&
    b3 === 0xaf &&
    b4 === 0x27 &&
    b5 === 0x1c
  ) {
    return "7z archive";
  }
  return null;
};

const detectXz = (dv: DataView): ProbeResult => {
  if (dv.byteLength < 6) return null;
  const b0 = dv.getUint8(0);
  const b1 = dv.getUint8(1);
  const b2 = dv.getUint8(2);
  const b3 = dv.getUint8(3);
  const b4 = dv.getUint8(4);
  const b5 = dv.getUint8(5);
  if (
    b0 === 0xfd &&
    b1 === 0x37 &&
    b2 === 0x7a &&
    b3 === 0x58 &&
    b4 === 0x5a &&
    b5 === 0x00
  ) {
    return "XZ compressed data";
  }
  return null;
};

const detectLz4 = (dv: DataView): ProbeResult => {
  if (dv.byteLength < 4) return null;
  const b0 = dv.getUint8(0);
  const b1 = dv.getUint8(1);
  const b2 = dv.getUint8(2);
  const b3 = dv.getUint8(3);
  if (b0 === 0x04 && b1 === 0x22 && b2 === 0x4d && b3 === 0x18) {
    return "LZ4 frame";
  }
  return null;
};

const detectZstd = (dv: DataView): ProbeResult => {
  if (dv.byteLength < 4) return null;
  const b0 = dv.getUint8(0);
  const b1 = dv.getUint8(1);
  const b2 = dv.getUint8(2);
  const b3 = dv.getUint8(3);
  if (b0 === 0x28 && b1 === 0xb5 && b2 === 0x2f && b3 === 0xfd) {
    return "Zstandard compressed data (zstd)";
  }
  return null;
};

const detectRar = (dv: DataView): ProbeResult => {
  if (dv.byteLength < 7) return null;
  const m =
    String.fromCharCode(dv.getUint8(0)) +
    String.fromCharCode(dv.getUint8(1)) +
    String.fromCharCode(dv.getUint8(2)) +
    String.fromCharCode(dv.getUint8(3));
  if (m !== "Rar!") return null;
  const b4 = dv.getUint8(4);
  const b5 = dv.getUint8(5);
  return b4 === 0x1a && b5 === 0x07 ? "RAR archive" : null;
};

const detectCab = (dv: DataView): ProbeResult => {
  if (dv.byteLength < 4) return null;
  const sig = dv.getUint32(0, false);
  return sig === 0x4d534346 ? "Microsoft Cabinet archive (CAB)" : null;
};

const detectTar = (dv: DataView): ProbeResult => {
  if (dv.byteLength < 262) return null;
  const offset = 257;
  const u =
    String.fromCharCode(dv.getUint8(offset + 0)) +
    String.fromCharCode(dv.getUint8(offset + 1)) +
    String.fromCharCode(dv.getUint8(offset + 2)) +
    String.fromCharCode(dv.getUint8(offset + 3)) +
    String.fromCharCode(dv.getUint8(offset + 4));
  return u === "ustar" ? "TAR archive" : null;
};

const detectIso9660 = (dv: DataView): ProbeResult => {
  const markers = [0x8001, 0x8801, 0x9001];
  for (let i = 0; i < markers.length; i += 1) {
    const offset = markers[i];
    if (offset === undefined) continue;
    if (dv.byteLength < offset + 5) continue;
    const s =
      String.fromCharCode(dv.getUint8(offset + 0)) +
      String.fromCharCode(dv.getUint8(offset + 1)) +
      String.fromCharCode(dv.getUint8(offset + 2)) +
      String.fromCharCode(dv.getUint8(offset + 3)) +
      String.fromCharCode(dv.getUint8(offset + 4));
    if (s === "CD001") {
      return "ISO-9660 CD/DVD image (ISO)";
    }
  }
  return null;
};

const archiveProbes: Array<(dv: DataView) => ProbeResult> = [
  detectZip,
  detectGzip,
  detectBzip2,
  detectSevenZip,
  detectXz,
  detectLz4,
  detectZstd,
  detectRar,
  detectCab,
  detectTar,
  detectIso9660
];

export { archiveProbes };
