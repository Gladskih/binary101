"use strict";
import type { PeDataDirectory, RvaToOffset } from "../types.js";
import {
  validateResourceDirectoryDuplicates,
  validateResourceDirectoryEntryKinds,
  validateResourceDirectoryIdSort,
  validateResourceDirectoryNameSort
} from "./directory-rules.js";
import type { ResourceDirectoryEntry } from "./directory-rules.js";
import { updateDirectoryLayoutEnd, validateResourceLayout } from "./layout-rules.js";
import type { ResourceDataEntryLayout, ResourceLayoutRange } from "./layout-rules.js";
import { createResourceSpanResolver } from "./relative-offsets.js";
import { knownResourceType } from "./type-names.js";
import type { ResourceDirectoryInfo, ResourceLeafPath, ResourcePathNode, ResourceTree } from "./tree-types.js";
import { createEmptyResourceTree, createResourceTreeResult } from "./tree-result.js";
import { buildResourcePathCollections } from "./tree-paths.js";
import { createFileRangeReader } from "../../file-range-reader.js";
export type { ResourceLangEntry, ResourceDetailEntry, ResourceTree } from "./tree-types.js";

// Microsoft PE format, ".rsrc Section":
// https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#the-rsrc-section
// IMAGE_RESOURCE_DIRECTORY and IMAGE_RESOURCE_DATA_ENTRY are 16 bytes; IMAGE_RESOURCE_DIRECTORY_ENTRY is 8 bytes.
const IMAGE_RESOURCE_DIRECTORY_SIZE = 16;
const IMAGE_RESOURCE_DIRECTORY_ENTRY_SIZE = 8;
const IMAGE_RESOURCE_DATA_ENTRY_SIZE = 16;
// Microsoft PE format, "Resource Directory Entries": the high bit distinguishes string-vs-ID
// names and subdirectory-vs-data targets.
// https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#resource-directory-entries
const RESOURCE_DIRECTORY_HIGH_BIT = 0x80000000;
const RESOURCE_DIRECTORY_OFFSET_MASK = 0x7fffffff;

export async function buildResourceTree(
  file: File,
  dataDirs: PeDataDirectory[],
  rvaToOff: RvaToOffset
): Promise<ResourceTree | null> {
  const utf16Decoder = new TextDecoder("utf-16le", { fatal: false });
  const dir = dataDirs.find(d => d.name === "RESOURCE");
  if (!dir?.rva) return null;
  if (dir.size < IMAGE_RESOURCE_DIRECTORY_SIZE) {
    return createEmptyResourceTree(
      dir,
      rvaToOff(dir.rva),
      [`Resource directory is smaller than IMAGE_RESOURCE_DIRECTORY (${IMAGE_RESOURCE_DIRECTORY_SIZE} bytes).`],
      rvaToOff
    );
  }
  const base = rvaToOff(dir.rva);
  if (base == null) {
    return createEmptyResourceTree(
      dir,
      null,
      ["Resource directory RVA does not map to file data."],
      rvaToOff
    );
  }
  if (base < 0 || base >= file.size) {
    return createEmptyResourceTree(
      dir,
      base,
      ["Resource directory starts outside file data."],
      rvaToOff
    );
  }
  const limitEnd = base + dir.size;
  const issues: string[] = [];
  let maxDirectoryEnd = 0;
  const resourceNameCache = new Map<number, Promise<string>>();
  const resourceDirectoryCache = new Map<
    number,
    Promise<{ Named: number; Ids: number; entries: ResourceDirectoryEntry[] } | null>
  >();
  const resourceStringRanges: ResourceLayoutRange[] = [];
  const resourceDataEntries: ResourceDataEntryLayout[] = [];
  const resourceSubdirectoryTargets: number[] = [];
  const directories: ResourceDirectoryInfo[] = [];
  const seenDirectoryOffsets = new Set<number>();
  const reader = createFileRangeReader(file, 0, file.size);
  const view = async (off: number, len: number): Promise<DataView> => reader.read(off, len);
  const u16 = (dv: DataView, off: number): number => dv.getUint16(off, true);
  const u32 = (dv: DataView, off: number): number => dv.getUint32(off, true);
  const addIssue = (message: string): void => {
    if (!issues.includes(message)) issues.push(message);
  };
  const { formatRelOffset, describeRelOffsetFailure, resolveRelOffset } =
    createResourceSpanResolver(dir.rva, dir.size, base, limitEnd, file.size, rvaToOff);
  const parseDir = (rel: number): Promise<{ Named: number; Ids: number; entries: ResourceDirectoryEntry[] } | null> => {
    const cached = resourceDirectoryCache.get(rel);
    if (cached) return cached;
    const pending = (async () => {
      const off = resolveRelOffset(rel, IMAGE_RESOURCE_DIRECTORY_SIZE);
      if (off == null) {
        addIssue(describeRelOffsetFailure(rel, IMAGE_RESOURCE_DIRECTORY_SIZE, `Resource directory at ${formatRelOffset(rel)}`));
        return null;
      }
      const dv = await view(off, IMAGE_RESOURCE_DIRECTORY_SIZE);
      // IMAGE_RESOURCE_DIRECTORY field offsets are Characteristics +0x00, TimeDateStamp +0x04,
      // MajorVersion +0x08, MinorVersion +0x0A, NumberOfNamedEntries +0x0C, NumberOfIdEntries +0x0E.
      if (dv.byteLength < IMAGE_RESOURCE_DIRECTORY_SIZE) {
        addIssue(`Resource directory header at ${formatRelOffset(rel)} is truncated.`);
        return null;
      }
      const characteristics = u32(dv, 0);
      if (characteristics !== 0) {
        addIssue(
          `IMAGE_RESOURCE_DIRECTORY.Characteristics at ${formatRelOffset(rel)} is non-zero; the field is reserved and should be 0.`
        );
      }
      const timeDateStamp = u32(dv, 4);
      const majorVersion = u16(dv, 8);
      const minorVersion = u16(dv, 10);
      const Named = u16(dv, 12);
      const Ids = u16(dv, 14);
      if (!seenDirectoryOffsets.has(rel)) {
        directories.push({
          offset: rel,
          characteristics,
          timeDateStamp,
          majorVersion,
          minorVersion,
          namedEntries: Named,
          idEntries: Ids
        });
        seenDirectoryOffsets.add(rel);
      }
      const count = Named + Ids;
      const entries: ResourceDirectoryEntry[] = [];
      for (let index = 0; index < count; index++) {
        const entryRel = rel + IMAGE_RESOURCE_DIRECTORY_SIZE + index * IMAGE_RESOURCE_DIRECTORY_ENTRY_SIZE;
        const entryOff = resolveRelOffset(entryRel, IMAGE_RESOURCE_DIRECTORY_ENTRY_SIZE);
        if (entryOff == null) {
          addIssue(
            `Resource directory entries for ${formatRelOffset(rel)} extend past the declared span.`
          );
          break;
        }
        const e = await view(entryOff, IMAGE_RESOURCE_DIRECTORY_ENTRY_SIZE);
        if (e.byteLength < IMAGE_RESOURCE_DIRECTORY_ENTRY_SIZE) {
          addIssue(`Resource directory entry at ${formatRelOffset(entryRel)} is truncated.`);
          break;
        }
        const Name = u32(e, 0);
        const OffsetToData = u32(e, 4);
        const nameIsString = (Name & RESOURCE_DIRECTORY_HIGH_BIT) !== 0;
        const subdir = (OffsetToData & RESOURCE_DIRECTORY_HIGH_BIT) !== 0;
        if (subdir && (OffsetToData & RESOURCE_DIRECTORY_OFFSET_MASK) === rel) {
          addIssue(`Resource directory at ${formatRelOffset(rel)} has a subdirectory entry that points to itself.`);
        }
        entries.push({
          nameIsString,
          subdir,
          nameOrId: nameIsString ? (Name & RESOURCE_DIRECTORY_OFFSET_MASK) : (Name >>> 0),
          target: OffsetToData & RESOURCE_DIRECTORY_OFFSET_MASK
        });
        if (subdir) resourceSubdirectoryTargets.push(OffsetToData & RESOURCE_DIRECTORY_OFFSET_MASK);
      }
      maxDirectoryEnd = updateDirectoryLayoutEnd(maxDirectoryEnd, rel, entries.length);
      validateResourceDirectoryEntryKinds(rel, Named, entries, addIssue);
      validateResourceDirectoryIdSort(rel, Named, entries, addIssue);
      await validateResourceDirectoryNameSort(rel, Named, entries, readUcs2Label, addIssue);
      await validateResourceDirectoryDuplicates(rel, entries, readUcs2Label, addIssue);
      return { Named, Ids, entries };
    })();
    resourceDirectoryCache.set(rel, pending);
    return pending;
  };
  const readUcs2Label = (rel: number): Promise<string> => {
    const cached = resourceNameCache.get(rel);
    if (cached) return cached;
    const pending = (async (): Promise<string> => {
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
      const dv = await view(so, 2);
      if (dv.byteLength < 2) {
        addIssue(`Resource string name header at ${formatRelOffset(rel)} is truncated.`);
        return "";
      }
      const len = u16(dv, 0);
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
  const root = await parseDir(0);
  if (!root) {
    return createResourceTreeResult(dir, base, limitEnd, issues, directories, [], [], [], view, rvaToOff);
  }
  const readPathNode = async (entry: ResourceDirectoryEntry): Promise<ResourcePathNode> => ({
    id: entry.nameIsString ? null : (entry.nameOrId ?? null),
    name: entry.nameIsString && entry.nameOrId != null ? await readUcs2Label(entry.nameOrId) : null
  });
  const readTypeName = async (entry: ResourceDirectoryEntry): Promise<string> => {
    if (!entry.nameIsString && entry.nameOrId != null) {
      return knownResourceType(entry.nameOrId) || `TYPE_${entry.nameOrId}`;
    }
    return entry.nameIsString && entry.nameOrId != null ? readUcs2Label(entry.nameOrId) : "(named)";
  };
  const readLeafPath = async (
    target: number,
    nodes: ResourcePathNode[]
  ): Promise<ResourceLeafPath | null> => {
    const dataEntryOff = resolveRelOffset(target, IMAGE_RESOURCE_DATA_ENTRY_SIZE);
    if (dataEntryOff == null) {
      addIssue(describeRelOffsetFailure(target, IMAGE_RESOURCE_DATA_ENTRY_SIZE, `Resource data entry at ${formatRelOffset(target)}`));
      return null;
    }
    const dv = await view(dataEntryOff, IMAGE_RESOURCE_DATA_ENTRY_SIZE);
    // IMAGE_RESOURCE_DATA_ENTRY field offsets are OffsetToData +0x00, Size +0x04,
    // CodePage +0x08, Reserved +0x0C.
    if (dv.byteLength < IMAGE_RESOURCE_DATA_ENTRY_SIZE) {
      addIssue(`Resource data entry at ${formatRelOffset(target)} is truncated.`);
      return null;
    }
    const dataRVA = u32(dv, 0);
    const size = u32(dv, 4);
    const codePage = u32(dv, 8);
    const reserved = u32(dv, 12);
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
  const { top, detail, paths } = await buildResourcePathCollections(
    root.entries,
    parseDir,
    readPathNode,
    readTypeName,
    readLeafPath,
    formatRelOffset,
    addIssue
  );
  validateResourceLayout(
    maxDirectoryEnd,
    resourceStringRanges,
    resourceDataEntries,
    resourceSubdirectoryTargets,
    dir.rva,
    dir.size,
    base,
    limitEnd,
    rvaToOff,
    file.size,
    addIssue
  );
  return createResourceTreeResult(
    dir,
    base,
    limitEnd,
    issues,
    directories,
    top,
    detail,
    paths,
    view,
    rvaToOff
  );
}
