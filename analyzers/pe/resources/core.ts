"use strict";
import type { FileRangeReader } from "../../file-range-reader.js";
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
import type { ResourceDirectoryInfo, ResourceTree } from "./tree-types.js";
import { createEmptyResourceTree, createResourceTreeResult } from "./tree-result.js";
import {
  createResourceLabelReader,
  createResourceLeafPathReader,
  createResourcePathNodeReader,
  createResourceTypeNameReader
} from "./tree-readers.js";
import { buildResourcePathCollections } from "./tree-paths.js";
export type { ResourceLangEntry, ResourceDetailEntry, ResourceTree } from "./tree-types.js";

// Microsoft PE format, ".rsrc Section":
// https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#the-rsrc-section
// IMAGE_RESOURCE_DIRECTORY and IMAGE_RESOURCE_DATA_ENTRY are 16 bytes; IMAGE_RESOURCE_DIRECTORY_ENTRY is 8 bytes.
const IMAGE_RESOURCE_DIRECTORY_SIZE = 16;
const IMAGE_RESOURCE_DIRECTORY_ENTRY_SIZE = 8;
// Microsoft PE format, "Resource Directory Entries": the high bit distinguishes string-vs-ID
// names and subdirectory-vs-data targets.
// https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#resource-directory-entries
const RESOURCE_DIRECTORY_HIGH_BIT = 0x80000000;
const RESOURCE_DIRECTORY_OFFSET_MASK = 0x7fffffff;

export async function buildResourceTree(
  reader: FileRangeReader,
  dataDirs: PeDataDirectory[],
  rvaToOff: RvaToOffset
): Promise<ResourceTree | null> {
  const utf16Decoder = new TextDecoder("utf-16le", { fatal: false });
  const dir = dataDirs.find(d => d.name === "RESOURCE");
  if (!dir || (dir.rva === 0 && dir.size === 0)) return null;
  if (dir.rva === 0) {
    return createEmptyResourceTree(
      dir,
      rvaToOff(dir.rva),
      ["Resource directory has a non-zero size but RVA is 0."],
      rvaToOff
    );
  }
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
  if (base < 0 || base >= reader.size) {
    return createEmptyResourceTree(
      dir,
      base,
      ["Resource directory starts outside file data."],
      rvaToOff
    );
  }
  const limitEnd = base + dir.size;
  const issues = new Set<string>();
  let maxDirectoryEnd = 0;
  const resourceDirectoryCache = new Map<
    number,
    Promise<{ Named: number; Ids: number; entries: ResourceDirectoryEntry[] } | null>
  >();
  const resourceStringRanges: ResourceLayoutRange[] = [];
  const resourceDataEntries: ResourceDataEntryLayout[] = [];
  const resourceSubdirectoryTargets: number[] = [];
  const invalidResourceNameOffsets = new Set<number>();
  const directories: ResourceDirectoryInfo[] = [];
  const seenDirectoryOffsets = new Set<number>();
  const view = async (off: number, len: number): Promise<DataView> => reader.read(off, len);
  const u16 = (dv: DataView, off: number): number => dv.getUint16(off, true);
  const u32 = (dv: DataView, off: number): number => dv.getUint32(off, true);
  const addIssue = (message: string): void => {
    issues.add(message);
  };
  const { formatRelOffset, describeRelOffsetFailure, resolveRelOffset } =
    createResourceSpanResolver(dir.rva, dir.size, base, limitEnd, reader.size, rvaToOff);
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
      const availableEntryCount = Math.max(
        0,
        Math.floor((dir.size - (rel + IMAGE_RESOURCE_DIRECTORY_SIZE)) / IMAGE_RESOURCE_DIRECTORY_ENTRY_SIZE)
      );
      const entryCount = Math.min(count, availableEntryCount);
      const localDirectoryEnd = rel + IMAGE_RESOURCE_DIRECTORY_SIZE + entryCount * IMAGE_RESOURCE_DIRECTORY_ENTRY_SIZE;
      if (entryCount < count) {
        addIssue(
          `Resource directory at ${formatRelOffset(rel)} declares ${count} entries, `
            + `but only ${entryCount} fit in the declared span.`
        );
      }
      const entries: ResourceDirectoryEntry[] = [];
      const entriesRel = rel + IMAGE_RESOURCE_DIRECTORY_SIZE;
      const entriesByteLength = entryCount * IMAGE_RESOURCE_DIRECTORY_ENTRY_SIZE;
      const entriesOff = resolveRelOffset(entriesRel, entriesByteLength);
      if (entriesByteLength > 0 && entriesOff != null) {
        const entriesView = await view(entriesOff, entriesByteLength);
        for (let index = 0; index < entryCount; index++) {
          const entryOffset = index * IMAGE_RESOURCE_DIRECTORY_ENTRY_SIZE;
          const Name = u32(entriesView, entryOffset);
          const OffsetToData = u32(entriesView, entryOffset + 4);
          const nameIsString = (Name & RESOURCE_DIRECTORY_HIGH_BIT) !== 0;
          const subdir = (OffsetToData & RESOURCE_DIRECTORY_HIGH_BIT) !== 0;
          const nameOrId = nameIsString ? (Name & RESOURCE_DIRECTORY_OFFSET_MASK) : (Name >>> 0);
          if (nameIsString && nameOrId < localDirectoryEnd) {
            invalidResourceNameOffsets.add(nameOrId);
            addIssue(
              `Resource string name at ${formatRelOffset(nameOrId)} points into the directory-entry area.`
            );
          }
          if (subdir && (OffsetToData & RESOURCE_DIRECTORY_OFFSET_MASK) === rel) {
            addIssue(`Resource directory at ${formatRelOffset(rel)} has a subdirectory entry that points to itself.`);
          }
          entries.push({
            nameIsString,
            subdir,
            nameOrId,
            target: OffsetToData & RESOURCE_DIRECTORY_OFFSET_MASK
          });
          if (subdir) resourceSubdirectoryTargets.push(OffsetToData & RESOURCE_DIRECTORY_OFFSET_MASK);
        }
      } else {
        for (let index = 0; index < entryCount; index++) {
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
          const nameOrId = nameIsString ? (Name & RESOURCE_DIRECTORY_OFFSET_MASK) : (Name >>> 0);
          if (nameIsString && nameOrId < localDirectoryEnd) {
            invalidResourceNameOffsets.add(nameOrId);
            addIssue(
              `Resource string name at ${formatRelOffset(nameOrId)} points into the directory-entry area.`
            );
          }
          if (subdir && (OffsetToData & RESOURCE_DIRECTORY_OFFSET_MASK) === rel) {
            addIssue(`Resource directory at ${formatRelOffset(rel)} has a subdirectory entry that points to itself.`);
          }
          entries.push({
            nameIsString,
            subdir,
            nameOrId,
            target: OffsetToData & RESOURCE_DIRECTORY_OFFSET_MASK
          });
          if (subdir) resourceSubdirectoryTargets.push(OffsetToData & RESOURCE_DIRECTORY_OFFSET_MASK);
        }
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
  const readUcs2Label = createResourceLabelReader(
    reader,
    dir,
    invalidResourceNameOffsets,
    resolveRelOffset,
    describeRelOffsetFailure,
    formatRelOffset,
    utf16Decoder,
    resourceStringRanges,
    addIssue
  );
  const root = await parseDir(0);
  if (!root) {
    return createResourceTreeResult(
      dir,
      base,
      limitEnd,
      [...issues],
      directories,
      [],
      [],
      [],
      view,
      rvaToOff
    );
  }
  const readPathNode = createResourcePathNodeReader(readUcs2Label);
  const readTypeName = createResourceTypeNameReader(readUcs2Label);
  const readLeafPath = createResourceLeafPathReader(
    view,
    resolveRelOffset,
    describeRelOffsetFailure,
    formatRelOffset,
    resourceDataEntries,
    addIssue
  );
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
    reader.size,
    addIssue
  );
  return createResourceTreeResult(
    dir,
    base,
    limitEnd,
    [...issues],
    directories,
    top,
    detail,
    paths,
    view,
    rvaToOff
  );
}
