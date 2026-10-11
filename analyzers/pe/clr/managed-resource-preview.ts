"use strict";

import { addHeuristicBinaryResourcePreview } from "../resources/preview/sniff.js";
import { parseBrowserManifestXmlDocument } from "../resources/preview/manifest-xml.js";
import { addXmlTextResourcePreviewWithParser } from "../resources/preview/xml.js";
import type { ResourcePreviewResult } from "../resources/preview/types.js";

const decodeManagedText = (bytes: Uint8Array): { text: string; encoding: string } | null => {
  // Unicode BOMs: https://www.unicode.org/faq/utf_bom.html
  const encoding = bytes[0] === 0xff && bytes[1] === 0xfe ? "utf-16le" :
    bytes[0] === 0xfe && bytes[1] === 0xff ? "utf-16be" : "utf-8";
  try {
    const text = new TextDecoder(encoding, { fatal: true }).decode(bytes);
    return text && isPlainText(text)
      ? { text, encoding: encoding.toUpperCase() } : null;
  } catch {
    return null;
  }
};

const isPlainText = (text: string): boolean => {
  for (const character of text) {
    const code = character.charCodeAt(0);
    if (code === 127 || (code < 32 && ![9, 10, 13].includes(code))) return false;
  }
  return true;
};

export const previewManagedResourceText = (text: string): ResourcePreviewResult => {
  // Require tag/declaration syntax before considering arbitrary managed strings XML candidates.
  // This is a candidate test; DOMParser validates the markup and reports malformed XML.
  if (/^(?:<\?xml\s|<!--|<!DOCTYPE\s|<[^\s<>?!/]+(?:\s*\/?>|\s+[^\s<>/=]+\s*=))/u
    .test(text.trimStart())) {
    return addXmlTextResourcePreviewWithParser(text, "XMLFILE", undefined, parseBrowserManifestXmlDocument);
  }
  return { preview: { previewKind: "text", textPreview: text } };
};

export const previewManagedResourceBytes = async (
  bytes: Uint8Array
): Promise<ResourcePreviewResult | null> => {
  const sniffed = await addHeuristicBinaryResourcePreview(bytes);
  if (sniffed) return sniffed;
  const decoded = decodeManagedText(bytes);
  if (!decoded) return null;
  const result = previewManagedResourceText(decoded.text);
  return {
    ...result, preview: {
      ...result.preview!, textEncoding: decoded.encoding,
      previewFields: result.preview!.previewFields ?? [{ label: "Detected", value: "Text (heuristic)" }]
    }
  };
};
