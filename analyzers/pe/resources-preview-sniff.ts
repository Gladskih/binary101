"use strict";

import { parseAni } from "../ani/index.js";
import { makeDataUrl } from "./resource-preview-data-url.js";
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
} from "./resource-preview-signatures.js";
import type {
  ResourcePreviewField,
  ResourcePreviewResult
} from "./resources-preview-types.js";
import { decodeTextResource } from "./resources-preview-text.js";

const isAsciiWhitespace = (byte: number): boolean =>
  byte === 0x09 || byte === 0x0a || byte === 0x0d || byte === 0x20;

const buildDataPreview = (
  previewKind: "image" | "audio" | "font",
  mimeType: string,
  data: Uint8Array,
  fields: ResourcePreviewField[] = []
): ResourcePreviewResult | null => {
  if (data.length > 2 * 1024 * 1024) return null; // UI policy: avoid very large inline data URLs.
  return {
    preview: {
      previewKind,
      previewMime: mimeType,
      previewDataUrl: makeDataUrl(mimeType, data),
      ...(fields.length ? { previewFields: fields } : {})
    }
  };
};

const buildSummaryPreview = (
  fields: ResourcePreviewField[]
): ResourcePreviewResult => ({
  preview: {
    previewKind: "summary",
    previewFields: fields
  }
});

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
  if (trimmed.startsWith("{") || trimmed.startsWith("[")) return "JSON/Text";
  if (/^[A-Za-z0-9_.-]+\s*=/.test(trimmed)) return "INI/Text";
  return "Text";
};

const addTextSniffPreview = (
  data: Uint8Array,
  codePage: number | undefined
): ResourcePreviewResult | null => {
  // Windows code page 1200 identifies UTF-16LE.
  if (!looksTextual(data) && codePage !== 1200) return null;
  const decoded = decodeTextResource(data, codePage);
  if (!decoded.text) return null;
  const preview = {
    previewKind: "text",
    textPreview: decoded.text.slice(0, 1024), // UI policy: cap heuristic text previews to 1 KiB.
    ...(decoded.encoding ? { textEncoding: decoded.encoding } : {})
  };
  const detectedFormat = detectTextFormat(decoded.text);
  return {
    preview: {
      ...preview,
      ...(detectedFormat
        ? { previewFields: [{ label: "Detected", value: `${detectedFormat} (heuristic)` }] }
        : {})
    }
  };
};

const addAniSummaryPreview = async (data: Uint8Array): Promise<ResourcePreviewResult | null> => {
  if (!hasRiffForm(data, "ACON")) return null;
  const payload = data.buffer.slice(data.byteOffset, data.byteOffset + data.byteLength) as ArrayBuffer;
  const parsed = await parseAni(new File([payload], "resource.ani", { type: "application/octet-stream" }));
  if (!parsed) return null;
  return buildSummaryPreview([
    { label: "Detected", value: "Animated cursor/icon (ANI, heuristic)" },
    { label: "Frames", value: String(parsed.header?.frameCount ?? parsed.frames) },
    { label: "Steps", value: String(parsed.header?.stepCount ?? parsed.sequence.length) }
  ]);
};

export const addHeuristicResourcePreview = async (
  data: Uint8Array,
  codePage: number | undefined
): Promise<ResourcePreviewResult | null> => {
  if (!data.length) return null;
  if (hasPngSignature(data)) {
    return buildDataPreview("image", "image/png", data, [{ label: "Detected", value: "PNG (heuristic)" }]);
  }
  if (hasJpegSignature(data)) {
    return buildDataPreview("image", "image/jpeg", data, [{ label: "Detected", value: "JPEG (heuristic)" }]);
  }
  if (hasGifSignature(data)) {
    return buildDataPreview("image", "image/gif", data, [{ label: "Detected", value: "GIF (heuristic)" }]);
  }
  if (hasBmpSignature(data)) {
    return buildDataPreview("image", "image/bmp", data, [{ label: "Detected", value: "BMP (heuristic)" }]);
  }
  if (hasWebpSignature(data)) {
    return buildDataPreview("image", "image/webp", data, [{ label: "Detected", value: "WebP (heuristic)" }]);
  }
  // RIFF WAVE form type. Source: Microsoft RIFF Multimedia Programming Interface and Data
  // Specifications 1.0 / https://www.mmsp.ece.mcgill.ca/Documents/AudioFormats/WAVE/Docs/riffmci.pdf
  if (hasRiffForm(data, "WAVE")) {
    return buildDataPreview("audio", "audio/wav", data, [{ label: "Detected", value: "WAV (heuristic)" }]);
  }
  const aniPreview = await addAniSummaryPreview(data);
  if (aniPreview) return aniPreview;
  if (hasTrueTypeSfntSignature(data)) {
    return buildDataPreview("font", "font/ttf", data, [{ label: "Detected", value: "TrueType font (heuristic)" }]);
  }
  if (hasOpenTypeCffSignature(data)) {
    return buildDataPreview("font", "font/otf", data, [{ label: "Detected", value: "OpenType font (heuristic)" }]);
  }
  if (hasWoffSignature(data)) {
    return buildDataPreview("font", "font/woff", data, [{ label: "Detected", value: "WOFF font (heuristic)" }]);
  }
  if (hasWoff2Signature(data)) {
    return buildDataPreview("font", "font/woff2", data, [{ label: "Detected", value: "WOFF2 font (heuristic)" }]);
  }
  if (hasPdfHeader(data)) {
    return buildSummaryPreview([{ label: "Detected", value: "PDF document (heuristic)" }]);
  }
  if (hasZipLocalFileHeader(data)) {
    return buildSummaryPreview([{ label: "Detected", value: "ZIP archive (heuristic)" }]);
  }
  // RIFF AVI form type.
  if (hasRiffForm(data, "AVI ")) {
    return buildSummaryPreview([{ label: "Detected", value: "AVI container (heuristic)" }]);
  }
  return addTextSniffPreview(data, codePage);
};
