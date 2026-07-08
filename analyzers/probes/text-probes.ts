"use strict";
import { isMostlyText, toAsciiPrefix, MAX_TEXT_INSPECT_BYTES } from "./text-heuristics.js";
import type { ProbeResult } from "./probe-types.js";

const MAX_SETUP_SCRIPT_INSPECT_BYTES = 2048;

const hasUtf16Bom = (dv: DataView): boolean =>
  dv.byteLength >= 2 &&
  (
    (dv.getUint8(0) === 0xff && dv.getUint8(1) === 0xfe) ||
    (dv.getUint8(0) === 0xfe && dv.getUint8(1) === 0xff)
  );

const toUtf16Prefix = (dv: DataView, maxBytes: number, littleEndian: boolean): string => {
  const limit = Math.min(dv.byteLength, maxBytes);
  let result = "";
  for (let offset = 2; offset + 1 < limit; offset += 2) {
    const code = dv.getUint16(offset, littleEndian);
    if (code === 0) break;
    result += String.fromCharCode(code);
  }
  return result;
};

const toTextPrefix = (dv: DataView, maxBytes: number): string => {
  if (dv.byteLength >= 2 && dv.getUint8(0) === 0xff && dv.getUint8(1) === 0xfe) {
    return toUtf16Prefix(dv, maxBytes, true);
  }
  if (dv.byteLength >= 2 && dv.getUint8(0) === 0xfe && dv.getUint8(1) === 0xff) {
    return toUtf16Prefix(dv, maxBytes, false);
  }
  return toAsciiPrefix(dv, maxBytes);
};

const detectScriptShebang = (dv: DataView): ProbeResult => {
  if (dv.byteLength < 2) return null;
  const b0 = dv.getUint8(0);
  const b1 = dv.getUint8(1);
  if (b0 === 0x23 && b1 === 0x21) return "Text script (shebang)";
  return null;
};

const detectHtml = (dv: DataView): ProbeResult => {
  const text = toTextPrefix(dv, MAX_TEXT_INSPECT_BYTES).trimStart().toLowerCase();
  if (text.startsWith("<!doctype html") || text.startsWith("<html")) {
    return "HTML document";
  }
  return null;
};

const detectXmlOrSvg = (dv: DataView): ProbeResult => {
  const text = toTextPrefix(dv, MAX_TEXT_INSPECT_BYTES).trimStart();
  const lower = text.toLowerCase();
  if (!lower.startsWith("<?xml")) return null;
  if (lower.includes("<svg")) return "SVG image (XML)";
  return "XML document";
};

const detectJson = (dv: DataView): ProbeResult => {
  const text = toTextPrefix(dv, MAX_TEXT_INSPECT_BYTES).trimStart();
  if (!text) return null;
  const first = text[0];
  if (first !== "{" && first !== "[") return null;
  const hasQuote = text.indexOf("\"") !== -1;
  const hasColon = text.indexOf(":") !== -1;
  if (!hasQuote && !hasColon) return null;
  return "JSON data";
};

const detectRtf = (dv: DataView): ProbeResult => {
  const text = toTextPrefix(dv, MAX_TEXT_INSPECT_BYTES).trimStart();
  if (!text) return null;
  if (text.startsWith("{\\rtf")) return "RTF document";
  return null;
};

const detectFb2Xml = (dv: DataView): ProbeResult => {
  const text = toTextPrefix(dv, MAX_TEXT_INSPECT_BYTES).trimStart().toLowerCase();
  if (!text) return null;
  if (text.indexOf("<fictionbook") !== -1) return "FictionBook e-book (FB2)";
  return null;
};

const detectWindowsSetupScript = (dv: DataView): ProbeResult => {
  const text = toTextPrefix(dv, MAX_SETUP_SCRIPT_INSPECT_BYTES).toLowerCase();
  if (!text.includes("[version]") || !text.includes("signature")) return null;
  if (text.includes("$windows nt$") || text.includes("$chicago$")) {
    return "Windows setup information file (INF, driver/install directives)";
  }
  return null;
};

const detectPlainText = (dv: DataView): ProbeResult => {
  if (!isMostlyText(dv) && !hasUtf16Bom(dv)) return null;
  return "Text file";
};

const TEXT_PROBES: Array<(dv: DataView) => ProbeResult> = [
  detectScriptShebang,
  detectHtml,
  detectFb2Xml,
  detectXmlOrSvg,
  detectWindowsSetupScript,
  detectRtf,
  detectJson,
  detectPlainText
];

const probeTextLike = (dv: DataView): ProbeResult => {
  if (!isMostlyText(dv) && !hasUtf16Bom(dv)) return null;
  for (const probe of TEXT_PROBES) {
    const label = probe(dv);
    if (label) return label;
  }
  return null;
};

export { probeTextLike };
