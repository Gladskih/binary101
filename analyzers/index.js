"use strict";

import { parsePe } from "./pe/index.js";
import { peProbe, mapMachine } from "./pe/signature.js";
import { probeByMagic, probeTextLike } from "./probes.js";
import { parseJpeg } from "./jpeg/index.js";

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

function toAsciiFromWholeView(dv, maxBytes) {
  const limit = Math.min(dv.byteLength, maxBytes);
  let result = "";
  for (let i = 0; i < limit; i += 1) {
    result += String.fromCharCode(dv.getUint8(i));
  }
  return result;
}

function refineZipLabel(dv) {
  const ascii = toAsciiFromWholeView(dv, 65536);
  const hasContentTypes = ascii.indexOf("[Content_Types].xml") !== -1;
  const hasRelsRoot = ascii.indexOf("_rels/.rels") !== -1;
  const hasWord = ascii.indexOf("word/") !== -1;
  const hasXl = ascii.indexOf("xl/") !== -1;
  const hasPpt = ascii.indexOf("ppt/") !== -1;
  const hasFb2Entry = ascii.indexOf(".fb2") !== -1;
  const hasOdtMime =
    ascii.indexOf("application/vnd.oasis.opendocument.text") !== -1;
  const hasOdsMime =
    ascii.indexOf("application/vnd.oasis.opendocument.spreadsheet") !== -1;
  const hasOdpMime =
    ascii.indexOf("application/vnd.oasis.opendocument.presentation") !== -1;
  const hasEpubMime = ascii.indexOf("application/epub+zip") !== -1;
  const hasJarManifest = ascii.indexOf("META-INF/MANIFEST.MF") !== -1;
  const hasAndroidManifest = ascii.indexOf("AndroidManifest.xml") !== -1;
  const hasDex = ascii.indexOf("classes.dex") !== -1;
  const hasVsixManifest = ascii.indexOf("extension.vsixmanifest") !== -1;
  const hasXpsFixedSeq =
    ascii.indexOf("FixedDocSeq.fdseq") !== -1 ||
    ascii.indexOf("FixedDocumentSequence.fdseq") !== -1;
  if (hasOdtMime) return "OpenDocument text document (ODT)";
  if (hasOdsMime) return "OpenDocument spreadsheet (ODS)";
  if (hasOdpMime) return "OpenDocument presentation (ODP)";
  if (hasEpubMime) return "EPUB e-book";
  if (hasJarManifest && hasAndroidManifest && hasDex) {
    return "Android application package (APK)";
  }
  if (hasVsixManifest) return "Visual Studio extension package (VSIX)";
  if (hasJarManifest) return "Java archive (JAR/WAR/EAR/JMOD)";
  if (hasXpsFixedSeq) return "XPS document";
  if (hasFb2Entry) return "FictionBook e-book inside ZIP (FB2)";
  if (hasContentTypes && hasWord) return "Microsoft Word document (DOCX)";
  if (hasContentTypes && hasXl) return "Microsoft Excel workbook (XLSX)";
  if (hasContentTypes && hasPpt) return "Microsoft PowerPoint presentation (PPTX)";
  if (hasContentTypes || hasRelsRoot) return "OpenXML Office document (DOCX/XLSX/PPTX)";
  return null;
}

function refineCompoundLabel(dv) {
  const ascii = toAsciiFromWholeView(dv, 65536);
  if (ascii.indexOf("PowerPoint Document") !== -1) {
    return "Microsoft PowerPoint binary document (PPT)";
  }
  if (ascii.indexOf("WordDocument") !== -1) {
    return "Microsoft Word binary document (DOC)";
  }
  if (ascii.indexOf("Workbook") !== -1 || ascii.indexOf("Book") !== -1) {
    return "Microsoft Excel binary workbook (XLS)";
  }
  if (ascii.indexOf("MSISummaryInformation") !== -1 || ascii.indexOf(".Transform") !== -1) {
    return "Windows Installer package (MSI)";
  }
  if (ascii.indexOf("ITSF") !== -1 || ascii.indexOf("::DataSpace") !== -1) {
    return "Microsoft Compiled HTML Help (CHM) or related";
  }
  return null;
}

export async function detectBinaryType(file) {
  const maxProbeBytes = Math.min(file.size || 0, 65536);
  const dv = new DataView(
    await file.slice(0, Math.min(file.size, maxProbeBytes)).arrayBuffer()
  );
  const e = detectELF(dv);
  if (e) return e;
  const m = detectMachO(dv);
  if (m) return m;
  const magic = probeByMagic(dv);
  if (magic) {
    if (magic.startsWith("ZIP archive")) {
      const zipLabel = refineZipLabel(dv);
      if (zipLabel) return zipLabel;
    }
    if (magic.startsWith("Microsoft Compound File")) {
      const compound = refineCompoundLabel(dv);
      if (compound) return compound;
    }
    return magic;
  }
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
  const text = probeTextLike(dv);
  if (text) return text;
  return "Unknown binary type";
}

// Parse-and-render entry point (current: PE only)
export async function parseForUi(file) {
  const dv = new DataView(
    await file.slice(0, Math.min(file.size, 65536)).arrayBuffer()
  );
  if (peProbe(dv)) {
    const pe = await parsePe(file);
    return { analyzer: "pe", parsed: pe };
  }
  if (dv.byteLength >= 2 && dv.getUint16(0, false) === 0xffd8) {
    const jpeg = await parseJpeg(file);
    if (jpeg) return { analyzer: "jpeg", parsed: jpeg };
  }
  return { analyzer: null, parsed: null };
}
