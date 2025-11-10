"use strict";

import { parsePe, peProbe, mapMachine } from "./pe.js";

// Quick magic-based detectors for non-PE types (label only for now)
function detectELF(dv) {
  if (dv.byteLength < 0x14) return null;
  if (dv.getUint32(0, false) !== 0x7f454c46) return null; // '\x7FELF'
  const c = dv.getUint8(4), d = dv.getUint8(5);
  const le = d === 1; const t = dv.getUint16(0x10, le), m = dv.getUint16(0x12, le);
  const bit = c === 1 ? "32-bit" : c === 2 ? "64-bit" : "?";
  const endian = d === 1 ? "LSB" : d === 2 ? "MSB" : "?";
  const mach = m === 0x3e ? "x86-64" : m === 0x03 ? "x86" : m === 0xb7 ? "ARM64" : m === 0x28 ? "ARM" : ("machine=" + m.toString(16));
  const kind = t === 2 ? "executable" : t === 3 ? "shared object" : t === 1 ? "relocatable" : ("type=" + t.toString(16));
  return `ELF ${bit} ${endian} ${kind}, ${mach}`;
}

function detectMachO(dv) {
  if (dv.byteLength < 4) return null;
  const be = dv.getUint32(0, false), le = dv.getUint32(0, true);
  if (be === 0xfeedface || le === 0xcefaedfe) return "Mach-O 32-bit";
  if (be === 0xfeedfacf || le === 0xcffaedfe) return "Mach-O 64-bit";
  if (be === 0xcafebabe || le === 0xbebafeca) return "Mach-O universal (Fat)";
  return null;
}

export async function detectBinaryType(file) {
  const dv = new DataView(await file.slice(0, Math.min(file.size, 64)).arrayBuffer());
  const detectPDF = dv => dv.byteLength >= 5 && String.fromCharCode(dv.getUint8(0)) + String.fromCharCode(dv.getUint8(1)) + String.fromCharCode(dv.getUint8(2)) + String.fromCharCode(dv.getUint8(3)) + String.fromCharCode(dv.getUint8(4)) === "%PDF-" ? "PDF document" : null;
  const detectZIP = dv => dv.byteLength >= 4 && dv.getUint32(0, true) === 0x04034b50 ? "ZIP archive (PK)" : null;
  const detectGZIP = dv => dv.byteLength >= 2 && dv.getUint16(0, true) === 0x8b1f ? "gzip compressed data" : null;
  const detectPNG = dv => dv.byteLength >= 8 && dv.getUint32(0, false) === 0x89504e47 && dv.getUint32(4, false) === 0x0d0a1a0a ? "PNG image" : null;
  const e = detectELF(dv); if (e) return e;
  const m = detectMachO(dv); if (m) return m;
  const p = detectPDF(dv); if (p) return p;
  const z = detectZIP(dv); if (z) return z;
  const gz = detectGZIP(dv); if (gz) return gz;
  const png = detectPNG(dv); if (png) return png;
  const probe = peProbe(dv);
  if (probe) {
    const pe = await parsePe(file);
    if (pe) {
      const sig = pe.opt.isPlus ? "PE32+" : "PE32";
      const isDll = (pe.coff.Characteristics & 0x2000) !== 0 ? "DLL" : "executable";
      return `${sig} ${isDll} for ${mapMachine(pe.coff.Machine)}`;
    }
    return "PE (unreadable)";
  }
  return "Unknown binary type";
}

// Parse-and-render entry point (current: PE only)
export async function parseForUi(file) {
  const dv = new DataView(await file.slice(0, Math.min(file.size, 64)).arrayBuffer());
  const probe = peProbe(dv);
  if (probe) {
    const pe = await parsePe(file);
    return { analyzer: "pe", parsed: pe };
  }
  return { analyzer: null, parsed: null };
}
