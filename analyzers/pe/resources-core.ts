"use strict";

import type { AddCoverageRegion, PeDataDirectory, RvaToOffset } from "./types.js";

const knownResourceType = (id: number): string | null => ({
  1: "CURSOR", 2: "BITMAP", 3: "ICON", 4: "MENU", 5: "DIALOG", 6: "STRING", 7: "FONTDIR", 8: "FONT", 9: "ACCELERATOR",
  10: "RCDATA", 11: "MESSAGETABLE", 12: "GROUP_CURSOR", 14: "GROUP_ICON", 16: "VERSION", 17: "DLGINCLUDE", 19: "PLUGPLAY",
  20: "VXD", 21: "ANICURSOR", 22: "ANIICON", 23: "HTML", 24: "MANIFEST"
})[id] || null;

export interface ResourceLangEntry {
  lang: number | null;
  size: number;
  codePage: number;
  dataRVA: number;
  reserved: number;
}

export interface ResourceDetailEntry {
  id: number | null;
  name: string | null;
  langs: ResourceLangEntry[];
}

export interface ResourceTree {
  base: number;
  limitEnd: number;
  dirRva?: number;
  dirSize?: number;
  issues?: string[];
  top: Array<{ typeName: string; kind: "name" | "id"; leafCount: number }>;
  detail: Array<{ typeName: string; entries: ResourceDetailEntry[] }>;
  view: (offset: number, length: number) => Promise<DataView>;
  rvaToOff: RvaToOffset;
}

export async function buildResourceTree(
  file: File,
  dataDirs: PeDataDirectory[],
  rvaToOff: RvaToOffset,
  addCoverageRegion: AddCoverageRegion
): Promise<ResourceTree | null> {
  const dir = dataDirs.find(d => d.name === "RESOURCE");
  if (!dir?.rva || dir.size < 16) return null;
  const base = rvaToOff(dir.rva);
  if (base == null) return null;
  addCoverageRegion("RESOURCE directory", base, dir.size);
  const limitEnd = base + dir.size;
  const issues: string[] = [];
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
      entries: Array<{ nameIsString: boolean; subdir: boolean; nameOrId: number | null; target: number }>;
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
    const Named = u16(dv, 12);
    const Ids = u16(dv, 14);
    const count = Named + Ids;
    const entries: Array<{
      nameIsString: boolean;
      subdir: boolean;
      nameOrId: number | null;
      target: number;
    }> = [];
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
      entries.push({
        nameIsString,
        subdir,
        nameOrId: nameIsString ? (Name & 0x7fffffff) : (Name >>> 0),
        target: OffsetToData & 0x7fffffff
      });
    }
    return { Named, Ids, entries };
  };

  const readUcs2Label = async (rel: number): Promise<string> => {
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
    let s = "";
    for (let index = 0; index + 1 < bytes.length; index += 2) {
      const first = bytes[index];
      const second = bytes[index + 1];
      if (first === undefined || second === undefined) break;
      const ch = first | (second << 8);
      if (ch === 0) break;
      s += String.fromCharCode(ch);
    }
    return s;
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

    if (typeEntry.subdir) {
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
          if (nameEntry.subdir) {
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
