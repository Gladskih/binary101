"use strict";
import { isMostlyText, MAX_TEXT_INSPECT_BYTES } from "./text-heuristics.js";
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
  const limit = Math.min(dv.byteLength, maxBytes);
  return new TextDecoder().decode(
    new Uint8Array(dv.buffer, dv.byteOffset, limit)
  );
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
  const rootName = findXmlRootName(text);
  if (rootName?.split(":").at(-1)?.toLowerCase() === "svg") return "SVG image (XML)";
  if (text.toLowerCase().startsWith("<?xml")) return "XML document";
  return rootName ? "XML document" : null;
};

const skipXmlPreamble = (text: string): string | null => {
  let remaining = text.trimStart();
  for (;;) {
    const closing = remaining.startsWith("<?")
      ? "?>"
      : remaining.startsWith("<!--")
        ? "-->"
        : remaining.toLowerCase().startsWith("<!doctype")
          ? ">"
          : null;
    if (!closing) return remaining;
    const end = remaining.indexOf(closing);
    if (end < 0) return null;
    remaining = remaining.slice(end + closing.length).trimStart();
  }
};

const findXmlRootName = (text: string): string | null => {
  const remaining = skipXmlPreamble(text);
  if (!remaining) return null;
  const match = /^<([A-Za-z_][\w:.-]*)(?:\s|\/?>)/u.exec(remaining);
  return match?.[1] ?? null;
};

const findJsonStringEnd = (text: string, start: number): number => {
  let escaped = false;
  for (let index = start + 1; index < text.length; index += 1) {
    if (!escaped && text[index] === "\"") return index;
    if (!escaped && text[index] === "\\") escaped = true;
    else escaped = false;
  }
  return -1;
};

const hasJsonObjectStart = (text: string): boolean => {
  const content = text.slice(1).trimStart();
  if (content.startsWith("}")) return true;
  if (!content.startsWith("\"")) return false;
  const stringEnd = findJsonStringEnd(content, 0);
  return stringEnd >= 0 && content.slice(stringEnd + 1).trimStart().startsWith(":");
};

const hasJsonArrayStart = (text: string): boolean => {
  const content = text.slice(1).trimStart();
  if (!content || content.startsWith("]") || content.startsWith("{") || content.startsWith("[")) {
    return Boolean(content);
  }
  if (content.startsWith("\"")) {
    const stringEnd = findJsonStringEnd(content, 0);
    return stringEnd >= 0 && /^[\s,\]]/u.test(content.slice(stringEnd + 1));
  }
  return /^(?:true|false|null|-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?)(?=\s*[,\]])/u
    .test(content);
};

const detectJson = (dv: DataView): ProbeResult => {
  const text = toTextPrefix(dv, MAX_TEXT_INSPECT_BYTES).trimStart();
  if (text.startsWith("{") && hasJsonObjectStart(text)) return "JSON data";
  if (text.startsWith("[") && hasJsonArrayStart(text)) return "JSON data";
  return null;
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

const detectPemArmor = (dv: DataView): ProbeResult => {
  const text = toTextPrefix(dv, MAX_TEXT_INSPECT_BYTES).trimStart();
  if (text.startsWith("-----BEGIN ") && text.includes("-----END ")) {
    return "PEM armor block (certificate/key text encoding)";
  }
  return null;
};

const detectPostScript = (dv: DataView): ProbeResult => {
  const text = toTextPrefix(dv, MAX_TEXT_INSPECT_BYTES).trimStart();
  return text.startsWith("%!") ? "PostScript document (page description program)" : null;
};

const detectPostScriptPrinterDescription = (dv: DataView): ProbeResult => {
  const text = toTextPrefix(dv, MAX_TEXT_INSPECT_BYTES).trimStart();
  return text.startsWith("*PPD-Adobe:")
    ? "PostScript Printer Description file (PPD printer driver metadata)"
    : null;
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
  detectPemArmor,
  detectPostScript,
  detectPostScriptPrinterDescription,
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
