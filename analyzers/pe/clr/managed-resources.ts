"use strict";

import type { FileRangeReader } from "../../file-range-reader.js";
import { addHeuristicResourcePreview } from "../resources/preview/sniff.js";
import type { ResourcePreviewData } from "../resources/preview/types.js";
import type { RvaToOffset } from "../types.js";
import type {
  PeClrHeader,
  PeClrManifestResourceInfo
} from "./types.js";
import { parseDotNetResources } from "./dotnet-resources.js";
import type {
  PeClrManagedResourceEntry,
  PeClrManagedResources
} from "./managed-resource-types.js";

const previewFields = (preview: ResourcePreviewData): Partial<PeClrManagedResourceEntry> => ({
  previewKind: preview.previewKind,
  ...(preview.previewMime ? { previewMime: preview.previewMime } : {}),
  ...(preview.previewDataUrl ? { previewDataUrl: preview.previewDataUrl } : {}),
  ...(preview.textPreview ? { textPreview: preview.textPreview } : {}),
  ...(preview.textEncoding !== undefined ? { textEncoding: preview.textEncoding } : {}),
  ...(preview.previewFields ? { previewFields: preview.previewFields } : {})
});

const readEmbeddedPayload = async (
  reader: FileRangeReader,
  rvaToOff: RvaToOffset,
  clr: PeClrHeader,
  row: PeClrManifestResourceInfo,
  issues: string[]
): Promise<{ storage: PeClrManagedResourceEntry["storage"]; bytes: Uint8Array | null; size: number | null }> => {
  if (row.offset < 0 || row.offset > clr.ResourcesSize || row.offset + 4 > clr.ResourcesSize) {
    issues.push(`Managed resource row ${row.row} offset is outside the CLR Resources directory.`);
    return { storage: "truncated", bytes: null, size: null };
  }
  const resourceRva = clr.ResourcesRVA + row.offset;
  if (!Number.isSafeInteger(resourceRva) || resourceRva > 0xffffffff) {
    issues.push(`Managed resource row ${row.row} RVA overflows 32-bit address space.`);
    return { storage: "unmapped", bytes: null, size: null };
  }
  const offset = rvaToOff(resourceRva);
  if (offset == null) return { storage: "unmapped", bytes: null, size: null };
  const lengthView = await reader.read(offset, 4);
  if (lengthView.byteLength < 4) return { storage: "truncated", bytes: null, size: null };
  const size = lengthView.getUint32(0, true);
  if (row.offset + 4 + size > clr.ResourcesSize) {
    issues.push(`Managed resource row ${row.row} payload extends past the CLR Resources directory.`);
    return { storage: "truncated", bytes: null, size };
  }
  // Local UI policy: match PE resource preview restraint by avoiding very large managed-resource reads.
  if (size > 8 * 1024 * 1024) {
    issues.push(`Managed resource payload is ${size} bytes; preview is capped.`);
    return { storage: "embedded", bytes: null, size };
  }
  const bytes = await reader.readBytes(offset + 4, size);
  if (bytes.length < size) return { storage: "truncated", bytes, size };
  return { storage: "embedded", bytes, size };
};

export const parseManagedResources = async (
  reader: FileRangeReader,
  rvaToOff: RvaToOffset,
  clr: PeClrHeader
): Promise<PeClrManagedResources | null> => {
  const rows = clr.meta?.tables?.manifestResources ?? [];
  if (!rows.length && clr.ResourcesRVA === 0 && clr.ResourcesSize === 0) return null;
  const issues: string[] = [];
  const entries: PeClrManagedResourceEntry[] = [];
  for (const row of rows) {
    if (row.implementation.valid && row.implementation.table !== "null") {
      entries.push({ ...row, storage: "external", size: null });
      continue;
    }
    const payload = await readEmbeddedPayload(reader, rvaToOff, clr, row, issues);
    const entryIssues: string[] = [];
    const dotNetEntries = payload.bytes ? await parseDotNetResources(payload.bytes, entryIssues) : null;
    const preview = payload.bytes && !dotNetEntries
      ? (await addHeuristicResourcePreview(payload.bytes, undefined))?.preview
      : null;
    entries.push({
      ...row,
      storage: payload.storage,
      size: payload.size,
      ...(dotNetEntries ? { entries: dotNetEntries } : {}),
      ...(preview ? previewFields(preview) : {}),
      ...(entryIssues.length ? { issues: entryIssues } : {})
    });
  }
  return { entries, issues };
};
