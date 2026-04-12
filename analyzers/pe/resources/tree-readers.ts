"use strict";

import type { FileRangeReader } from "../../file-range-reader.js";
import type { ResourceDirectoryEntry } from "./directory-rules.js";
import type { ResourceDataEntryLayout, ResourceLayoutRange } from "./layout-rules.js";
import { knownResourceType } from "./type-names.js";
import type { ResourceLeafPath, ResourcePathNode } from "./tree-types.js";
import type { PeDataDirectory } from "../types.js";

const IMAGE_RESOURCE_DATA_ENTRY_SIZE = 16;

export const createResourceLabelReader = (
  reader: FileRangeReader,
  dir: PeDataDirectory,
  invalidResourceNameOffsets: Set<number>,
  resolveRelOffset: (rel: number, len: number) => number | null,
  describeRelOffsetFailure: (rel: number, len: number, subject: string) => string,
  formatRelOffset: (rel: number) => string,
  utf16Decoder: TextDecoder,
  resourceStringRanges: ResourceLayoutRange[],
  addIssue: (message: string) => void
): ((rel: number) => Promise<string>) => {
  const resourceNameCache = new Map<number, Promise<string>>();
  const readUcs2Label = (rel: number): Promise<string> => {
    const cached = resourceNameCache.get(rel);
    if (cached) return cached;
    const pending = (async (): Promise<string> => {
      if (invalidResourceNameOffsets.has(rel)) {
        return "";
      }
      if ((rel & 1) !== 0) {
        addIssue(`Resource string name at ${formatRelOffset(rel)} is not word-aligned.`);
      }
      const so = resolveRelOffset(rel, 2);
      if (so == null) {
        addIssue(
          describeRelOffsetFailure(rel, 2, `Resource string name header at ${formatRelOffset(rel)}`)
        );
        return "";
      }
      const dv = await reader.read(so, 2);
      if (dv.byteLength < 2) {
        addIssue(`Resource string name header at ${formatRelOffset(rel)} is truncated.`);
        return "";
      }
      const len = dv.getUint16(0, true);
      const declaredBytesLength = len * 2;
      const bytesLength = Math.min(declaredBytesLength, Math.max(0, dir.size - (rel + 2)));
      resourceStringRanges.push({ start: rel, end: rel + 2 + bytesLength });
      if (bytesLength < declaredBytesLength) {
        addIssue(`Resource string name at ${formatRelOffset(rel)} is truncated.`);
      }
      const textOff = resolveRelOffset(rel + 2, bytesLength);
      if (textOff == null) {
        addIssue(
          describeRelOffsetFailure(
            rel + 2,
            bytesLength,
            `Resource string name payload at ${formatRelOffset(rel + 2)}`
          )
        );
        return "";
      }
      const bytesView = await reader.read(textOff, bytesLength);
      const bytes = new Uint8Array(
        bytesView.buffer,
        bytesView.byteOffset,
        bytesView.byteLength
      );
      return utf16Decoder.decode(bytes.subarray(0, bytes.length - (bytes.length % 2)));
    })();
    resourceNameCache.set(rel, pending);
    return pending;
  };
  return readUcs2Label;
};

export const createResourcePathNodeReader = (
  readUcs2Label: (rel: number) => Promise<string>
): ((entry: ResourceDirectoryEntry) => Promise<ResourcePathNode>) =>
  async (entry: ResourceDirectoryEntry): Promise<ResourcePathNode> => ({
    id: entry.nameIsString ? null : (entry.nameOrId ?? null),
    name:
      entry.nameIsString && entry.nameOrId != null
        ? await readUcs2Label(entry.nameOrId)
        : null
  });

export const createResourceTypeNameReader = (
  readUcs2Label: (rel: number) => Promise<string>
): ((entry: ResourceDirectoryEntry) => Promise<string>) =>
  async (entry: ResourceDirectoryEntry): Promise<string> => {
    if (!entry.nameIsString && entry.nameOrId != null) {
      return knownResourceType(entry.nameOrId) || `TYPE_${entry.nameOrId}`;
    }
    if (!entry.nameIsString || entry.nameOrId == null) {
      return "(named)";
    }
    return await readUcs2Label(entry.nameOrId);
  };

export const createResourceLeafPathReader = (
  view: (offset: number, length: number) => Promise<DataView>,
  resolveRelOffset: (rel: number, len: number) => number | null,
  describeRelOffsetFailure: (rel: number, len: number, subject: string) => string,
  formatRelOffset: (rel: number) => string,
  resourceDataEntries: ResourceDataEntryLayout[],
  addIssue: (message: string) => void
): ((target: number, nodes: ResourcePathNode[]) => Promise<ResourceLeafPath | null>) =>
  async (target: number, nodes: ResourcePathNode[]): Promise<ResourceLeafPath | null> => {
    const dataEntryOff = resolveRelOffset(target, IMAGE_RESOURCE_DATA_ENTRY_SIZE);
    if (dataEntryOff == null) {
      addIssue(
        describeRelOffsetFailure(
          target,
          IMAGE_RESOURCE_DATA_ENTRY_SIZE,
          `Resource data entry at ${formatRelOffset(target)}`
        )
      );
      return null;
    }
    const dv = await view(dataEntryOff, IMAGE_RESOURCE_DATA_ENTRY_SIZE);
    if (dv.byteLength < IMAGE_RESOURCE_DATA_ENTRY_SIZE) {
      addIssue(`Resource data entry at ${formatRelOffset(target)} is truncated.`);
      return null;
    }
    const dataRVA = dv.getUint32(0, true);
    const size = dv.getUint32(4, true);
    const codePage = dv.getUint32(8, true);
    const reserved = dv.getUint32(12, true);
    resourceDataEntries.push({
      start: target,
      end: target + IMAGE_RESOURCE_DATA_ENTRY_SIZE,
      dataRva: dataRVA,
      size
    });
    if (reserved !== 0) {
      addIssue("IMAGE_RESOURCE_DATA_ENTRY.Reserved is non-zero; the field should be 0.");
    }
    return {
      nodes,
      dataRVA,
      size,
      codePage,
      reserved
    };
  };
