"use strict";

import { addAniCursorPreview } from "./ani.js";
import { makeDataUrl } from "./data-url.js";
import {
  hasBmpSignature,
  hasGifSignature,
  hasJpegSignature,
  hasOpenTypeCffSignature,
  hasPdfHeader,
  hasPngSignature,
  hasRiffForm,
  hasTrueTypeSfntSignature,
  hasWebpSignature,
  hasWoffSignature,
  hasWoff2Signature,
  hasZipLocalFileHeader
} from "../../../probes/file-signatures.js";
import type {
  ResourcePreviewField,
  ResourcePreviewResult
} from "./types.js";
import { decodeTextResource } from "./text.js";
import { addDfmPreview } from "./dfm.js";
import { addTextDfmPreview } from "./dfm-text.js";
import { addMetafilePreview } from "./metafile.js";
import { addSvgTextPreview } from "./svg.js";
import { parseBrowserManifestXmlDocument } from "./manifest-xml.js";
import type { ManifestXmlDocumentParser } from "./manifest-xml.js";

const isAsciiWhitespace = (byte: number): boolean =>
  byte === 0x09 || byte === 0x0a || byte === 0x0d || byte === 0x20;

const buildDataPreview = (
  previewKind: "image" | "audio" | "font",
  mimeType: string,
  data: Uint8Array,
  fields: ResourcePreviewField[] = []
): ResourcePreviewResult | null => {
  return {
    preview: {
      previewKind,
      previewMime: mimeType,
      previewDataUrl: makeDataUrl(mimeType, data),
      ...(fields.length ? { previewFields: fields } : {})
    }
  };
};

const looksTextual = (data: Uint8Array): boolean => {
  if (!data.length) return false;
  let printable = 0;
  // Heuristic: sample at most 256 bytes and require 80% printable ASCII-ish content.
  const sample = data.subarray(0, Math.min(256, data.length));
  for (const byte of sample) {
    if (byte === 0) continue;
    if (isAsciiWhitespace(byte) || (byte >= 0x20 && byte <= 0x7e)) printable += 1;
  }
  return printable >= Math.floor(sample.length * 0.8);
};

const detectTextFormat = (text: string): string | null => {
  const trimmed = text.trimStart();
  if (!trimmed) return null;
  if (trimmed.startsWith("<?xml") || trimmed.startsWith("<")) return "XML/Text";
  // Windows INF files use bracketed section headers such as [Version].
  // https://learn.microsoft.com/en-us/windows-hardware/drivers/install/general-syntax-rules-for-inf-files
  if (/^\[[^\]\r\n]+\]\s*(?:\r?\n|$)/u.test(trimmed) || /^[A-Za-z0-9_.-]+\s*=/u.test(trimmed)) {
    return "INI/Text";
  }
  if (trimmed.startsWith("{") || trimmed.startsWith("[")) return "JSON/Text";
  return "Text";
};

const addTextSniffPreview = (
  data: Uint8Array,
  codePage: number | undefined
): ResourcePreviewResult | null => {
  const decoded = decodeTextResource(data, codePage);
  if (!decoded.text) return null;
  const sample = [...decoded.text.slice(0, 256)];
  const printable = sample.filter(character => (character.charCodeAt(0) >= 32 && character.charCodeAt(0) !== 127) || /[\t\r\n]/u.test(character));
  if (!looksTextual(data) && printable.length < sample.length * 0.8) return null;
  const preview = {
    previewKind: "text",
    textPreview: decoded.text,
    ...(decoded.encoding ? { textEncoding: decoded.encoding } : {})
  };
  const detectedFormat = detectTextFormat(decoded.text);
  return {
    preview: {
      ...preview,
      ...(detectedFormat
        ? { previewFields: [{ label: "Detected", value: `${detectedFormat} (heuristic)` }] }
        : {})
    },
    ...(decoded.error ? { issues: [String(decoded.error)] } : {})
  };
};

const addAniSummaryPreview = async (data: Uint8Array): Promise<ResourcePreviewResult | null> => {
  if (!hasRiffForm(data, "ACON")) return null;
  const result = await addAniCursorPreview(data, "ANICURSOR");
  if (!result?.preview) return result;
  return { ...result, preview: { ...result.preview, previewFields: [
    { label: "Detected", value: "Animated cursor/icon (ANI, heuristic)" },
    ...(result.preview.previewFields ?? []).filter(field => field.label !== "Type")
  ] } };
};

const hasValidIcoContainer = (data: Uint8Array): boolean => {
  // ICO = ICONDIR (6 bytes) + ICONDIRENTRY records (16 bytes each). ICONDIR shares
  // its leading fields with Microsoft ICONRESDIR:
  // https://learn.microsoft.com/en-us/windows/win32/menurc/iconresdir
  if (data.length < 22) return false;
  const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
  const count = view.getUint16(4, true);
  if (view.getUint16(0, true) !== 0 || view.getUint16(2, true) !== 1 || count === 0) return false;
  if (count > Math.floor((data.length - 6) / 16)) return false;
  return hasValidIcoImages(view, count);
};

const hasValidIcoImages = (view: DataView, count: number): boolean => {
  for (let index = 0; index < count; index += 1) {
    const entryOffset = 6 + index * 16;
    const imageSize = view.getUint32(entryOffset + 8, true);
    const imageOffset = view.getUint32(entryOffset + 12, true);
    if (imageSize === 0 || imageOffset < 6 + count * 16) return false;
    if (imageOffset > view.byteLength || imageSize > view.byteLength - imageOffset) return false;
  }
  return true;
};

const mediaFormats: Array<{ probe: (data: Uint8Array) => boolean;
  kind: "image" | "audio" | "font"; mime: string; name: string }> = [
  { probe: hasPngSignature, kind: "image", mime: "image/png", name: "PNG" },
  { probe: hasJpegSignature, kind: "image", mime: "image/jpeg", name: "JPEG" },
  { probe: hasGifSignature, kind: "image", mime: "image/gif", name: "GIF" },
  { probe: hasBmpSignature, kind: "image", mime: "image/bmp", name: "BMP" },
  { probe: hasWebpSignature, kind: "image", mime: "image/webp", name: "WebP" },
  { probe: hasValidIcoContainer, kind: "image", mime: "image/x-icon", name: "ICO" },
  { probe: data => hasRiffForm(data, "WAVE"), kind: "audio", mime: "audio/wav", name: "WAV" },
  { probe: hasTrueTypeSfntSignature, kind: "font", mime: "font/ttf", name: "TrueType font" },
  { probe: hasOpenTypeCffSignature, kind: "font", mime: "font/otf", name: "OpenType font" },
  { probe: hasWoffSignature, kind: "font", mime: "font/woff", name: "WOFF font" },
  { probe: hasWoff2Signature, kind: "font", mime: "font/woff2", name: "WOFF2 font" }
];
const documentFormats: Array<{ probe: (data: Uint8Array) => boolean; format: "PDF" | "ZIP" | "AVI" }> = [
  { probe: hasPdfHeader, format: "PDF" }, { probe: hasZipLocalFileHeader, format: "ZIP" },
  { probe: data => hasRiffForm(data, "AVI "), format: "AVI" }
];

export const addHeuristicBinaryResourcePreview = async (
  data: Uint8Array
): Promise<ResourcePreviewResult | null> => {
  const media = mediaFormats.find(format => format.probe(data));
  if (media) return buildDataPreview(media.kind, media.mime, data,
    [{ label: "Detected", value: `${media.name} (heuristic)` }]);
  const drawing = addMetafilePreview(data) ?? await addAniSummaryPreview(data);
  if (drawing) return drawing;
  const document = documentFormats.find(format => format.probe(data));
  return document ? { preview: { previewKind: "nested", embeddedDocument: { format: document.format } } } : null;
};

export const addHeuristicResourcePreview = async (
  data: Uint8Array, codePage: number | undefined,
  parseXml: ManifestXmlDocumentParser = parseBrowserManifestXmlDocument
): Promise<ResourcePreviewResult | null> => {
  const binary = addDfmPreview(data) ?? await addHeuristicBinaryResourcePreview(data);
  if (binary) return binary;
  const text = addTextSniffPreview(data, codePage);
  return text?.preview?.textPreview ? addTextDfmPreview(text.preview.textPreview) ??
    addSvgTextPreview(text.preview.textPreview, parseXml) ?? text : text;
};
