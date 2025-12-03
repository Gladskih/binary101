"use strict";
import { toAsciiPrefix } from "./text-heuristics.js";
import type { ProbeResult } from "./probe-types.js";

const detectPdf = (dv: DataView): ProbeResult => {
  if (dv.byteLength < 5) return null;
  const m =
    String.fromCharCode(dv.getUint8(0)) +
    String.fromCharCode(dv.getUint8(1)) +
    String.fromCharCode(dv.getUint8(2)) +
    String.fromCharCode(dv.getUint8(3)) +
    String.fromCharCode(dv.getUint8(4));
  return m === "%PDF-" ? "PDF document" : null;
};

const detectCompoundFile = (dv: DataView): ProbeResult => {
  if (dv.byteLength < 8) return null;
  const b0 = dv.getUint8(0);
  const b1 = dv.getUint8(1);
  const b2 = dv.getUint8(2);
  const b3 = dv.getUint8(3);
  const b4 = dv.getUint8(4);
  const b5 = dv.getUint8(5);
  const b6 = dv.getUint8(6);
  const b7 = dv.getUint8(7);
  if (
    b0 === 0xd0 &&
    b1 === 0xcf &&
    b2 === 0x11 &&
    b3 === 0xe0 &&
    b4 === 0xa1 &&
    b5 === 0xb1 &&
    b6 === 0x1a &&
    b7 === 0xe1
  ) {
    return "Microsoft Compound File (e.g. Office 97-2003, MSI)";
  }
  return null;
};

const detectPdb = (dv: DataView): ProbeResult => {
  if (dv.byteLength < 32) return null;
  const limit = Math.min(dv.byteLength, 64);
  let header = "";
  for (let i = 0; i < limit; i += 1) {
    const c = dv.getUint8(i);
    if (c === 0) break;
    header += String.fromCharCode(c);
  }
  if (!header) return null;
  const lower = header.toLowerCase();
  if (!lower.startsWith("microsoft c/c++")) return null;
  if (
    lower.indexOf("program database") !== -1 ||
    lower.indexOf("msf 7.00") !== -1
  ) {
    return "Microsoft PDB debug symbols";
  }
  return null;
};

const detectSqlite = (dv: DataView): ProbeResult => {
  if (dv.byteLength < 16) return null;
  const prefix = toAsciiPrefix(dv, 16);
  return prefix.startsWith("SQLite format 3") ? "SQLite 3.x database" : null;
};

const detectJavaClass = (dv: DataView): ProbeResult => {
  if (dv.byteLength < 4) return null;
  const sig = dv.getUint32(0, false);
  return sig === 0xcafebabe ? "Java class file" : null;
};

const detectDjvu = (dv: DataView): ProbeResult => {
  if (dv.byteLength < 16) return null;
  const header =
    String.fromCharCode(dv.getUint8(0)) +
    String.fromCharCode(dv.getUint8(1)) +
    String.fromCharCode(dv.getUint8(2)) +
    String.fromCharCode(dv.getUint8(3)) +
    String.fromCharCode(dv.getUint8(4)) +
    String.fromCharCode(dv.getUint8(5)) +
    String.fromCharCode(dv.getUint8(6)) +
    String.fromCharCode(dv.getUint8(7));
  if (header !== "AT&TFORM") return null;
  const id =
    String.fromCharCode(dv.getUint8(12)) +
    String.fromCharCode(dv.getUint8(13)) +
    String.fromCharCode(dv.getUint8(14)) +
    String.fromCharCode(dv.getUint8(15));
  if (id === "DJVU" || id === "DJVM" || id === "DJVI") {
    return "DjVu document";
  }
  return null;
};

const detectPcap = (dv: DataView): ProbeResult => {
  if (dv.byteLength < 4) return null;
  const sigBE = dv.getUint32(0, false);
  const sigLE = dv.getUint32(0, true);
  if (
    sigBE === 0xa1b2c3d4 ||
    sigBE === 0xa1b23c4d ||
    sigLE === 0xa1b2c3d4 ||
    sigLE === 0xa1b23c4d
  ) {
    return "PCAP capture file";
  }
  return null;
};

const detectPcapNg = (dv: DataView): ProbeResult => {
  if (dv.byteLength < 4) return null;
  const sig = dv.getUint32(0, false);
  return sig === 0x0a0d0d0a ? "PCAP-NG capture file" : null;
};

const detectLnk = (dv: DataView): ProbeResult => {
  if (dv.byteLength < 0x14) return null;
  const size = dv.getUint32(0, true);
  if (size !== 0x0000004c) return null;
  const clsid =
    dv.getUint32(4, true) === 0x00021401 &&
    dv.getUint16(8, true) === 0x0000 &&
    dv.getUint16(10, true) === 0x0000 &&
    dv.getUint8(12) === 0xc0 &&
    dv.getUint8(13) === 0x00 &&
    dv.getUint8(14) === 0x00 &&
    dv.getUint8(15) === 0x00 &&
    dv.getUint8(16) === 0x00 &&
    dv.getUint8(17) === 0x00 &&
    dv.getUint8(18) === 0x00 &&
    dv.getUint8(19) === 0x46;
  if (!clsid) return null;
  return "Windows shortcut (.lnk)";
};

const detectWasM = (dv: DataView): ProbeResult => {
  if (dv.byteLength < 4) return null;
  const sig = dv.getUint32(0, false);
  return sig === 0x0061736d ? "WebAssembly binary (WASM)" : null;
};

const detectDex = (dv: DataView): ProbeResult => {
  if (dv.byteLength < 8) return null;
  const prefix =
    String.fromCharCode(dv.getUint8(0)) +
    String.fromCharCode(dv.getUint8(1)) +
    String.fromCharCode(dv.getUint8(2)) +
    String.fromCharCode(dv.getUint8(3));
  if (prefix !== "dex\n") return null;
  return "Android DEX bytecode";
};

const detectWinHelp = (dv: DataView): ProbeResult => {
  if (dv.byteLength < 4) return null;
  const b0 = dv.getUint8(0);
  const b1 = dv.getUint8(1);
  const b2 = dv.getUint8(2);
  const b3 = dv.getUint8(3);
  if (b0 === 0x3f && b1 === 0x5f && b2 === 0x03 && b3 === 0x00) {
    return "Windows Help file (HLP)";
  }
  return null;
};

const miscProbes: Array<(dv: DataView) => ProbeResult> = [
  detectPdf,
  detectCompoundFile,
  detectPdb,
  detectSqlite,
  detectJavaClass,
  detectDjvu,
  detectPcapNg,
  detectPcap,
  detectLnk,
  detectWasM,
  detectDex,
  detectWinHelp
];

export { miscProbes };
