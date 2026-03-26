"use strict";

import type { AddCoverageRegion, PeDataDirectory, RvaToOffset } from "./types.js";
import { validateResourceDirectoryDuplicates, validateResourceDirectoryEntryKinds, validateResourceDirectoryIdSort, validateResourceDirectoryNameSort } from "./resource-directory-rules.js";
import type { ResourceDirectoryEntry } from "./resource-directory-rules.js";
import { updateDirectoryLayoutEnd, validateResourceLayout } from "./resource-layout-rules.js";
import type { ResourceDataEntryLayout, ResourceLayoutRange } from "./resource-layout-rules.js";
import { knownResourceType } from "./resource-type-names.js";
import type { ResourceDetailEntry, ResourceTree } from "./resource-tree-types.js";

export type { ResourceLangEntry, ResourceDetailEntry, ResourceTree } from "./resource-tree-types.js";

export async function buildResourceTree(
  file: File,
  dataDirs: PeDataDirectory[],
  rvaToOff: RvaToOffset,
  addCoverageRegion: AddCoverageRegion
): Promise<ResourceTree | null> {
  const utf16Decoder = new TextDecoder("utf-16le", { fatal: false });
  const dir = dataDirs.find(d => d.name === "RESOURCE");
  if (!dir?.rva || dir.size < 16) return null;
  const base = rvaToOff(dir.rva);
  if (base == null) return null;
  addCoverageRegion("RESOURCE directory", base, dir.size);
  const limitEnd = base + dir.size;
  const issues: string[] = [];
  let maxDirectoryEnd = 0;
  const resourceNameCache = new Map<number, Promise<string>>();
  const resourceStringRanges: ResourceLayoutRange[] = [];
  const resourceDataEntries: ResourceDataEntryLayout[] = [];
  const resourceSubdirectoryTargets: number[] = [];
  const view = async (off: number, len: number): Promise<DataView> =>
    new DataView(await file.slice(off, off + len).arrayBuffer());
  const u16 = (dv: DataView, off: number): number => dv.getUint16(off, true);
  const u32 = (dv: DataView, off: number): number => dv.getUint32(off, true);
  const addIssue = (message: string): void => {
    if (!issues.includes(message)) issues.push(message);
  };
  const formatRelOffset = (rel: number): string => `0x${(rel >>> 0).toString(16)}`;
  const describeRelOffsetFailure = (rel: number, len: number, subject: string): string => {
    if (rel < 0 || len < 0 || rel + len > dir.size) return `${subject} lies outside the declared span.`;
    const mappedOff = rvaToOff((dir.rva + rel) >>> 0);
    if (mappedOff != null && mappedOff >= 0 && mappedOff < file.size && mappedOff + len > file.size) {
      return `${subject} is truncated by end of file.`;
    }
    const fallbackOff = base + rel;
    if (fallbackOff >= base && fallbackOff < file.size && fallbackOff + len > file.size) {
      return `${subject} is truncated by end of file.`;
    }
    return `${subject} could not be mapped within the declared resource span.`;
  };
  const resolveRelOffset = (rel: number, len: number): number | null => {
    if (rel < 0 || len < 0 || rel + len > dir.size) return null;
    const mappedOff = rvaToOff((dir.rva + rel) >>> 0);
    if (mappedOff != null && mappedOff >= 0 && mappedOff + len <= file.size) {
      if (rel === 0 || mappedOff !== base) return mappedOff;
    }
    const fallbackOff = base + rel;
    if (fallbackOff < base || fallbackOff + len > limitEnd || fallbackOff + len > file.size) return null;
    return fallbackOff;
  };

  const parseDir = async (
    rel: number
  ): Promise<{
    Named: number;
      Ids: number;
      entries: ResourceDirectoryEntry[];
  } | null> => {
    const off = resolveRelOffset(rel, 16);
    if (off == null) {
      addIssue(describeRelOffsetFailure(rel, 16, `Resource directory at ${formatRelOffset(rel)}`));
      return null;
    }
    const dv = await view(off, 16);
    if (dv.byteLength < 16) {
      addIssue(`Resource directory header at ${formatRelOffset(rel)} is truncated.`);
      return null;
    }
    if (u32(dv, 0) !== 0) {
      addIssue(
        `IMAGE_RESOURCE_DIRECTORY.Characteristics at ${formatRelOffset(rel)} is non-zero; the field is reserved and should be 0.`
      );
    }
    const Named = u16(dv, 12);
    const Ids = u16(dv, 14);
    const count = Named + Ids;
    const entries: ResourceDirectoryEntry[] = [];
    for (let index = 0; index < count; index++) {
      const entryOff = resolveRelOffset(rel + 16 + index * 8, 8);
      if (entryOff == null) {
        addIssue(
          `Resource directory entries for ${formatRelOffset(rel)} extend past the declared span.`
        );
        break;
      }
      const e = await view(entryOff, 8);
      if (e.byteLength < 8) {
        addIssue(`Resource directory entry at ${formatRelOffset(rel + 16 + index * 8)} is truncated.`);
        break;
      }
      const Name = u32(e, 0);
      const OffsetToData = u32(e, 4);
      const nameIsString = (Name & 0x80000000) !== 0;
      const subdir = (OffsetToData & 0x80000000) !== 0;
      if (subdir && (OffsetToData & 0x7fffffff) === rel) {
        addIssue(`Resource directory at ${formatRelOffset(rel)} has a subdirectory entry that points to itself.`);
      }
      entries.push({
        nameIsString,
        subdir,
        nameOrId: nameIsString ? (Name & 0x7fffffff) : (Name >>> 0),
        target: OffsetToData & 0x7fffffff
      });
      if (subdir) resourceSubdirectoryTargets.push(OffsetToData & 0x7fffffff);
    }
    maxDirectoryEnd = updateDirectoryLayoutEnd(maxDirectoryEnd, rel, entries.length);
    validateResourceDirectoryEntryKinds(rel, Named, entries, addIssue);
    validateResourceDirectoryIdSort(rel, Named, entries, addIssue);
    await validateResourceDirectoryNameSort(rel, Named, entries, readUcs2Label, addIssue);
    await validateResourceDirectoryDuplicates(rel, entries, readUcs2Label, addIssue);
    return { Named, Ids, entries };
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
      const bytes = new Uint8Array(await file.slice(textOff, textOff + bytesLength).arrayBuffer());
      return utf16Decoder.decode(bytes.subarray(0, bytes.length - (bytes.length % 2)));
    })();
    resourceNameCache.set(rel, pending);
    return pending;
  };

  const root = await parseDir(0);
  if (!root) {
    return {
      base,
      limitEnd,
      dirRva: dir.rva,
      dirSize: dir.size,
      ...(issues.length ? { issues } : {}),
      top: [],
      detail: [],
      view,
      rvaToOff
    };
  }

  const top: Array<{ typeName: string; kind: "name" | "id"; leafCount: number }> = [];
  const detail: Array<{ typeName: string; entries: ResourceDetailEntry[] }> = [];

  for (const typeEntry of root.entries) {
    let typeName = "(named)";
    if (!typeEntry.nameIsString && typeEntry.nameOrId != null) {
      typeName = knownResourceType(typeEntry.nameOrId) || `TYPE_${typeEntry.nameOrId}`;
    } else if (typeEntry.nameIsString && typeEntry.nameOrId != null) {
      typeName = await readUcs2Label(typeEntry.nameOrId);
    }

    let leafCount = 0;
    const typeDetailEntries: ResourceDetailEntry[] = [];

    if (!typeEntry.subdir) {
      addIssue(
        `Top-level resource type entry ${typeName} points directly to data; type entries should point to second-level subdirectories.`
      );
    } else {
      const nameDir = await parseDir(typeEntry.target);
      if (nameDir) {
        for (const nameEntry of nameDir.entries) {
          const child: ResourceDetailEntry = {
            id: nameEntry.nameIsString ? null : nameEntry.nameOrId ?? null,
            name: null,
            langs: []
          };
          if (nameEntry.nameIsString && nameEntry.nameOrId != null) {
            child.name = await readUcs2Label(nameEntry.nameOrId);
          }
          if (!nameEntry.subdir) {
            addIssue(
              `Resource entry under type ${typeName} points directly to data; second-level entries should point to language subdirectories.`
            );
          } else {
            const langDir = await parseDir(nameEntry.target);
            if (langDir) {
              for (const langEnt of langDir.entries) {
                if (langEnt.subdir) {
                  addIssue(
                    `Resource language entry at ${formatRelOffset(langEnt.target)} points to a subdirectory.`
                  );
                  continue;
                }
                const dataEntryOff = resolveRelOffset(langEnt.target, 16);
                if (dataEntryOff == null) {
                  addIssue(
                    describeRelOffsetFailure(
                      langEnt.target,
                      16,
                      `Resource data entry at ${formatRelOffset(langEnt.target)}`
                    )
                  );
                  continue;
                }
                const dv = await view(dataEntryOff, 16);
                if (dv.byteLength < 16) {
                  addIssue(`Resource data entry at ${formatRelOffset(langEnt.target)} is truncated.`);
                  continue;
                }
                const DataRVA = u32(dv, 0);
                const Size = u32(dv, 4);
                const CodePage = u32(dv, 8);
                const Reserved = u32(dv, 12);
                resourceDataEntries.push({
                  start: langEnt.target,
                  end: langEnt.target + 16,
                  dataRva: DataRVA,
                  size: Size
                });
                if (Reserved !== 0) {
                  addIssue("IMAGE_RESOURCE_DATA_ENTRY.Reserved is non-zero; the field should be 0.");
                }
                const lang = langEnt.nameIsString ? null : (langEnt.nameOrId ?? null);
                const langEntry = { lang, size: Size, codePage: CodePage, dataRVA: DataRVA, reserved: Reserved };
                child.langs.push(langEntry);
                leafCount++;
              }
            }
          }
          if (child.langs.length) typeDetailEntries.push(child);
        }
      }
    }

    top.push({ typeName, kind: typeEntry.nameIsString ? "name" : "id", leafCount });
    if (typeDetailEntries.length) detail.push({ typeName, entries: typeDetailEntries });
  }

  validateResourceLayout(
    maxDirectoryEnd,
    resourceStringRanges,
    resourceDataEntries,
    resourceSubdirectoryTargets,
    rvaToOff,
    file.size,
    addIssue
  );
  return {
    base,
    limitEnd,
    dirRva: dir.rva,
    dirSize: dir.size,
    ...(issues.length ? { issues } : {}),
    top,
    detail,
    view,
    rvaToOff
  };
}
