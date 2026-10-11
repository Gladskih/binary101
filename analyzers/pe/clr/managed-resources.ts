"use strict";

import { readMappedRvaPrefix } from "../rva-byte-reader.js";
import type { FileRangeReader } from "../../file-range-reader.js";
import { previewManagedResourceBytes } from "./managed-resource-preview.js";
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

const hasExternalImplementation = (row: PeClrManifestResourceInfo): boolean =>
  row.implementation.valid && row.implementation.row > 0 && row.implementation.table !== "null";

const hasInvalidImplementation = (row: PeClrManifestResourceInfo): boolean =>
  row.implementation.raw !== 0 && !row.implementation.valid;

const isResourceRvaValid = (rva: number): boolean => Number.isSafeInteger(rva) && rva <= 0xffffffff;

const manifestResourceRows = (clr: PeClrHeader): PeClrManifestResourceInfo[] =>
  clr.meta?.tables?.manifestResources ?? [];

const readEmbeddedPayload = async (
  reader: FileRangeReader,
  rvaToOff: RvaToOffset,
  clr: PeClrHeader,
  row: PeClrManifestResourceInfo,
  issues: string[]
): Promise<{ storage: PeClrManagedResourceEntry["storage"]; bytes: Uint8Array | null; size: number | null }> => {
  if (row.offset < 0 || row.offset + 4 > clr.ResourcesSize) {
    issues.push(`Managed resource row ${row.row} offset is outside the CLR Resources directory.`);
    return { storage: "truncated", bytes: null, size: null };
  }
  const resourceRva = clr.ResourcesRVA + row.offset;
  if (!isResourceRvaValid(resourceRva)) {
    issues.push(`Managed resource row ${row.row} RVA overflows 32-bit address space.`);
    return { storage: "unmapped", bytes: null, size: null };
  }
  const offset = rvaToOff(resourceRva);
  if (offset == null) {
    issues.push(`Managed resource row ${row.row} length prefix is unmapped.`);
    return { storage: "unmapped", bytes: null, size: null };
  }
  const lengthView = await readMappedRvaPrefix(reader, resourceRva, 4, rvaToOff);
  if (lengthView.byteLength < 4) {
    issues.push(`Managed resource row ${row.row} length prefix is truncated.`);
    return { storage: "truncated", bytes: null, size: null };
  }
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
  const view = await readMappedRvaPrefix(reader, resourceRva + 4, size, rvaToOff);
  const bytes = new Uint8Array(view.buffer, view.byteOffset, view.byteLength);
  if (bytes.length < size) {
    issues.push(`Managed resource row ${row.row} payload is truncated (${bytes.length} of ${size} bytes).`);
    return { storage: "truncated", bytes: null, size };
  }
  return { storage: "embedded", bytes, size };
};

const parseEmbeddedResource = async (
  reader: FileRangeReader, rvaToOff: RvaToOffset, clr: PeClrHeader,
  row: PeClrManifestResourceInfo, issues: string[]
): Promise<PeClrManagedResourceEntry> => {
  const payload = await readEmbeddedPayload(reader, rvaToOff, clr, row, issues);
  const entryIssues: string[] = [];
  const dotNetEntries = payload.bytes ? await parseDotNetResources(payload.bytes, entryIssues) : null;
  const preview = payload.bytes && !dotNetEntries
    ? await previewManagedResourceBytes(payload.bytes) : null;
  entryIssues.push(...preview?.issues ?? []);
  return {
    ...row, storage: payload.storage, size: payload.size,
    ...(dotNetEntries ? { entries: dotNetEntries } : {}),
    ...preview?.preview,
    ...(entryIssues.length ? { issues: entryIssues } : {})
  };
};

export const parseManagedResources = async (
  reader: FileRangeReader,
  rvaToOff: RvaToOffset,
  clr: PeClrHeader
): Promise<PeClrManagedResources | null> => {
  const rows = manifestResourceRows(clr);
  if (!rows.length && clr.ResourcesRVA === 0 && clr.ResourcesSize === 0) return null;
  const issues: string[] = [];
  const entries: PeClrManagedResourceEntry[] = [];
  const embedded = new Map<number, PeClrManagedResourceEntry>();
  for (const row of rows) {
    if (hasExternalImplementation(row)) {
      entries.push({ ...row, storage: "external", size: null });
      continue;
    }
    if (hasInvalidImplementation(row)) {
      issues.push(`Managed resource row ${row.row} has an invalid Implementation metadata index.`);
      entries.push({ ...row, storage: "unmapped", size: null });
      continue;
    }
    const cached = embedded.get(row.offset);
    if (cached) {
      entries.push({ ...cached, ...row });
      continue;
    }
    const entry = await parseEmbeddedResource(reader, rvaToOff, clr, row, issues);
    embedded.set(row.offset, entry);
    entries.push(entry);
  }
  return { entries, issues };
};
