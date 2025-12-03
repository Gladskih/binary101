"use strict";

const toAsciiFromWholeView = (dv: DataView, maxBytes: number): string => {
  const limit = Math.min(dv.byteLength, maxBytes);
  let result = "";
  for (let i = 0; i < limit; i += 1) {
    result += String.fromCharCode(dv.getUint8(i));
  }
  return result;
};

const refineZipLabel = (dv: DataView): string | null => {
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
};

const detectPdfVersion = (dv: DataView): string | null => {
  const ascii = toAsciiFromWholeView(dv, 32);
  if (!ascii.startsWith("%PDF-")) return null;
  const match = ascii.match(/%PDF-([0-9]+\.[0-9]+)/);
  return match?.[1] ?? null;
};

const refineCompoundLabel = (dv: DataView): string | null => {
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
};

const hasZipEocdSignature = (dv: DataView): boolean => {
  if (dv.byteLength < 22) return false;
  const maxScanBytes = Math.min(dv.byteLength, 65535 + 22);
  for (let i = dv.byteLength - 22; i >= dv.byteLength - maxScanBytes && i >= 0; i--) {
    if (dv.getUint32(i, true) === 0x06054b50) {
      return true;
    }
  }
  return false;
};

export {
  detectPdfVersion,
  hasZipEocdSignature,
  refineCompoundLabel,
  refineZipLabel,
  toAsciiFromWholeView
};
