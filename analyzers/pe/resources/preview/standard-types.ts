"use strict";

import { addHeuristicResourcePreview } from "./sniff.js";
import { decodeTextResource } from "./text.js";
import type { ResourcePreviewField, ResourcePreviewResult } from "./types.js";

const buildSummaryPreview = (
  previewFields: ResourcePreviewField[],
  issues?: string[]
): ResourcePreviewResult => ({
  preview: {
    previewKind: "summary",
    previewFields
  },
  ...(issues?.length ? { issues } : {})
});

const prependTypeField = (
  typeName: string,
  preview: ResourcePreviewResult
): ResourcePreviewResult =>
  preview.preview
    ? {
        ...preview,
        preview: {
          ...preview.preview,
          previewFields: [
            { label: "Type", value: typeName },
            ...(preview.preview.previewFields || [])
          ]
        }
      }
    : preview;

const buildBinarySummary = (typeName: string, dataLength: number, note: string): ResourcePreviewResult =>
  buildSummaryPreview([
    { label: "Type", value: typeName },
    { label: "Size", value: `${dataLength} bytes` },
    { label: "Note", value: note }
  ]);

export const addRcDataPreview = async (
  data: Uint8Array,
  typeName: string,
  codePage: number | undefined
): Promise<ResourcePreviewResult | null> => {
  if (typeName !== "RCDATA") return null;
  const heuristic = await addHeuristicResourcePreview(data, codePage);
  if (heuristic?.preview) return prependTypeField(typeName, heuristic);
  return buildBinarySummary(typeName, data.length, "Application-defined raw data.");
};

export const addFontPreview = async (
  data: Uint8Array,
  typeName: string
): Promise<ResourcePreviewResult | null> => {
  if (typeName !== "FONT") return null;
  const heuristic = await addHeuristicResourcePreview(data, 0);
  if (heuristic?.preview) return prependTypeField(typeName, heuristic);
  return buildBinarySummary(typeName, data.length, "Legacy FONT resource payload.");
};

export const addFontDirectoryPreview = (
  data: Uint8Array,
  typeName: string
): ResourcePreviewResult | null => {
  if (typeName !== "FONTDIR") return null;
  return buildBinarySummary(typeName, data.length, "Font-directory resource table.");
};

export const addDialogIncludePreview = (
  data: Uint8Array,
  typeName: string,
  codePage: number | undefined
): ResourcePreviewResult | null => {
  if (typeName !== "DLGINCLUDE") return null;
  const issues: string[] = [];
  const decoded = decodeTextResource(data, codePage);
  if (decoded.error) issues.push("DLGINCLUDE text could not be fully decoded.");
  if (decoded.text) {
    return {
      preview: {
        previewKind: "text",
        textPreview: decoded.text,
        ...(decoded.encoding ? { textEncoding: decoded.encoding } : {}),
        previewFields: [{ label: "Type", value: "DLGINCLUDE" }]
      },
      ...(issues.length ? { issues } : {})
    };
  }
  return buildBinarySummary(typeName, data.length, "DLGINCLUDE resource content.");
};

export const addPlugPlayPreview = (
  data: Uint8Array,
  typeName: string
): ResourcePreviewResult | null =>
  typeName === "PLUGPLAY"
    ? buildBinarySummary(typeName, data.length, "Legacy Plug and Play resource.")
    : null;

export const addVxdPreview = (
  data: Uint8Array,
  typeName: string
): ResourcePreviewResult | null =>
  typeName === "VXD"
    ? buildBinarySummary(typeName, data.length, "Legacy virtual-device resource.")
    : null;
