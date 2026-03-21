"use strict";

import { addIconPreview, addGroupIconPreview } from "./resources-preview-icon.js";
import {
  addHtmlPreview,
  addManifestPreview,
  addPreviewIssue,
  addStringTablePreview,
  addVersionPreview
} from "./resources-preview-text.js";
import { decodeMessageTablePreview } from "./resources-preview-message-table.js";
import type { ResourceDetailGroup, ResourceLangWithPreview } from "./resources-preview-types.js";
import type { ResourceTree } from "./resources-core.js";

// Win32 STRINGTABLE resources pack 16 strings into each block.
const STRING_TABLE_ENTRY_COUNT = 16;
// winnt.h: IMAGE_RESOURCE_DIRECTORY is 16 bytes.
const RESOURCE_DIRECTORY_HEADER_SIZE = 16;
// winnt.h: IMAGE_RESOURCE_DIRECTORY_ENTRY is 8 bytes.
const RESOURCE_DIRECTORY_ENTRY_SIZE = 8;
// winnt.h: high bit marks a string name or subdirectory; low 31 bits store the directory-relative offset.
const RESOURCE_DIRECTORY_FLAG_MASK = 0x80000000; // IMAGE_RESOURCE_NAME_IS_STRING / IMAGE_RESOURCE_DATA_IS_DIRECTORY.
const RESOURCE_DIRECTORY_OFFSET_MASK = 0x7fffffff; // IMAGE_RESOURCE_* offset in the low 31 bits.
const RESOURCE_INTEGER_ID_MASK = 0xffff; // Integer resource ids are 16-bit values.

const truncateStringTablePreview = (langEntry: ResourceLangWithPreview): void => {
  if (langEntry.previewKind !== "stringTable") return;
  if (langEntry.stringPreview?.length && langEntry.stringPreview.length > STRING_TABLE_ENTRY_COUNT) {
    langEntry.stringPreview = langEntry.stringPreview.slice(0, STRING_TABLE_ENTRY_COUNT);
  }
  if (langEntry.stringTable?.length && langEntry.stringTable.length > STRING_TABLE_ENTRY_COUNT) {
    langEntry.stringTable = langEntry.stringTable.slice(0, STRING_TABLE_ENTRY_COUNT);
  }
};

export async function enrichResourcePreviews(
  file: File,
  tree: ResourceTree
): Promise<{ top: ResourceTree["top"]; detail: ResourceDetailGroup[]; issues?: string[] }> {
  const { base, limitEnd, top, view, rvaToOff } = tree;
  const detail = tree.detail as ResourceDetailGroup[];
  const issues = [...(tree.issues || [])];
  const addIssue = (message: string): void => {
    if (!issues.includes(message)) issues.push(message);
  };
  const formatRelOffset = (rel: number): string => `0x${(rel >>> 0).toString(16)}`;
  const resolveDirOffset = (rel: number, len: number): number | null => {
    if (tree.dirRva != null && tree.dirSize != null) {
      if (rel < 0 || len < 0 || rel + len > tree.dirSize) return null;
      const off = rvaToOff((tree.dirRva + rel) >>> 0);
      if (off == null || off < 0 || off + len > file.size) return null;
      return off;
    }
    const off = base + rel;
    if (off < base || len < 0 || off + len > limitEnd) return null;
    return off;
  };

  const iconIndex = new Map<number, { rva: number; size: number }>();
  const rootDirOff = resolveDirOffset(0, RESOURCE_DIRECTORY_HEADER_SIZE);
  if (rootDirOff == null) {
    addIssue("Resource preview could not read the root directory header.");
    return { top, detail, ...(issues.length ? { issues } : {}) };
  }
  const rootDirView = await view(rootDirOff, RESOURCE_DIRECTORY_HEADER_SIZE);
  if (rootDirView.byteLength < RESOURCE_DIRECTORY_HEADER_SIZE) {
    addIssue("Resource preview encountered a truncated root directory header.");
    return { top, detail, ...(issues.length ? { issues } : {}) };
  }
  const NamedRoot = rootDirView.getUint16(RESOURCE_DIRECTORY_HEADER_SIZE - 4, true);
  const IdsRoot = rootDirView.getUint16(RESOURCE_DIRECTORY_HEADER_SIZE - 2, true);
  const countRoot = NamedRoot + IdsRoot;
  for (let index = 0; index < countRoot; index += 1) {
    const entryOff = resolveDirOffset(
      RESOURCE_DIRECTORY_HEADER_SIZE + index * RESOURCE_DIRECTORY_ENTRY_SIZE,
      RESOURCE_DIRECTORY_ENTRY_SIZE
    );
    if (entryOff == null) {
      addIssue("Resource preview found a root directory entry outside the declared resource span.");
      break;
    }
    const e = await view(entryOff, RESOURCE_DIRECTORY_ENTRY_SIZE);
    if (e.byteLength < RESOURCE_DIRECTORY_ENTRY_SIZE) {
      addIssue("Resource preview encountered a truncated root directory entry.");
      break;
    }
    const Name = e.getUint32(0, true);
    const OffsetToData = e.getUint32(4, true);
    const subdir = (OffsetToData & RESOURCE_DIRECTORY_FLAG_MASK) !== 0;
    const id = (Name & RESOURCE_DIRECTORY_FLAG_MASK) ? null : (Name & RESOURCE_INTEGER_ID_MASK);
    if (id !== 3 /* RT_ICON */ || !subdir) continue;
    const nameDirRel = OffsetToData & RESOURCE_DIRECTORY_OFFSET_MASK;
    const nameDirOff = resolveDirOffset(nameDirRel, RESOURCE_DIRECTORY_HEADER_SIZE);
    if (nameDirOff == null) {
      addIssue(`Resource preview could not map the RT_ICON name directory at ${formatRelOffset(nameDirRel)}.`);
      continue;
    }
    const nameDirView = await view(nameDirOff, RESOURCE_DIRECTORY_HEADER_SIZE);
    if (nameDirView.byteLength < RESOURCE_DIRECTORY_HEADER_SIZE) {
      addIssue(`Resource preview found a truncated RT_ICON name directory at ${formatRelOffset(nameDirRel)}.`);
      continue;
    }
    const Named = nameDirView.getUint16(RESOURCE_DIRECTORY_HEADER_SIZE - 4, true);
    const Ids = nameDirView.getUint16(RESOURCE_DIRECTORY_HEADER_SIZE - 2, true);
    const count = Named + Ids;
    for (let idx = 0; idx < count; idx += 1) {
      const entry2Off = resolveDirOffset(
        nameDirRel + RESOURCE_DIRECTORY_HEADER_SIZE + idx * RESOURCE_DIRECTORY_ENTRY_SIZE,
        RESOURCE_DIRECTORY_ENTRY_SIZE
      );
      if (entry2Off == null) {
        addIssue(`Resource preview found an RT_ICON entry outside the declared span at ${formatRelOffset(nameDirRel)}.`);
        break;
      }
      const e2 = await view(entry2Off, RESOURCE_DIRECTORY_ENTRY_SIZE);
      if (e2.byteLength < RESOURCE_DIRECTORY_ENTRY_SIZE) {
        addIssue(`Resource preview found a truncated RT_ICON entry at ${formatRelOffset(nameDirRel)}.`);
        break;
      }
      const Name2 = e2.getUint32(0, true);
      const OffsetToData2 = e2.getUint32(4, true);
      const subdir2 = (OffsetToData2 & RESOURCE_DIRECTORY_FLAG_MASK) !== 0;
      const id2 = (Name2 & RESOURCE_DIRECTORY_FLAG_MASK) ? null : (Name2 & RESOURCE_INTEGER_ID_MASK);
      if (!subdir2) continue;
      const langDirRel = OffsetToData2 & RESOURCE_DIRECTORY_OFFSET_MASK;
      const langDirOff = resolveDirOffset(langDirRel, RESOURCE_DIRECTORY_HEADER_SIZE);
      if (langDirOff == null) {
        addIssue(`Resource preview could not map the RT_ICON language directory at ${formatRelOffset(langDirRel)}.`);
        continue;
      }
      const langDirView = await view(langDirOff, RESOURCE_DIRECTORY_HEADER_SIZE);
      if (langDirView.byteLength < RESOURCE_DIRECTORY_HEADER_SIZE) {
        addIssue(`Resource preview found a truncated RT_ICON language directory at ${formatRelOffset(langDirRel)}.`);
        continue;
      }
      const NamedL = langDirView.getUint16(RESOURCE_DIRECTORY_HEADER_SIZE - 4, true);
      const IdsL = langDirView.getUint16(RESOURCE_DIRECTORY_HEADER_SIZE - 2, true);
      const countL = NamedL + IdsL;
      for (let j = 0; j < countL; j += 1) {
        const langEntryOff = resolveDirOffset(
          langDirRel + RESOURCE_DIRECTORY_HEADER_SIZE + j * RESOURCE_DIRECTORY_ENTRY_SIZE,
          RESOURCE_DIRECTORY_ENTRY_SIZE
        );
        if (langEntryOff == null) {
          addIssue(`Resource preview found an RT_ICON language entry outside the declared span at ${formatRelOffset(langDirRel)}.`);
          break;
        }
        const le = await view(langEntryOff, RESOURCE_DIRECTORY_ENTRY_SIZE);
        if (le.byteLength < RESOURCE_DIRECTORY_ENTRY_SIZE) {
          addIssue(`Resource preview found a truncated RT_ICON language entry at ${formatRelOffset(langDirRel)}.`);
          break;
        }
        const OffsetToDataL = le.getUint32(4, true);
        const subdirL = (OffsetToDataL & RESOURCE_DIRECTORY_FLAG_MASK) !== 0;
        if (subdirL) continue;
        const dataRel = OffsetToDataL & RESOURCE_DIRECTORY_OFFSET_MASK;
        const deo2 = resolveDirOffset(dataRel, RESOURCE_DIRECTORY_HEADER_SIZE);
        if (deo2 == null) {
          addIssue(`Resource preview could not map the RT_ICON data entry at ${formatRelOffset(dataRel)}.`);
          continue;
        }
        const dv2 = await view(deo2, RESOURCE_DIRECTORY_HEADER_SIZE);
        if (dv2.byteLength < 8) {
          addIssue(`Resource preview found a truncated RT_ICON data entry at ${formatRelOffset(dataRel)}.`);
          continue;
        }
        const rva2 = dv2.getUint32(0, true);
        const sz2 = dv2.getUint32(4, true);
        if (id2 != null) iconIndex.set(id2, { rva: rva2, size: sz2 });
        break;
      }
    }
  }

  for (const group of detail) {
    const typeName = group.typeName;
    for (const entry of group.entries) {
      for (const langEntry of entry.langs as ResourceLangWithPreview[]) {
        if (!langEntry.size || !langEntry.dataRVA) continue;
        try {
          const dataOff = rvaToOff(langEntry.dataRVA);
          if (dataOff == null) {
            addPreviewIssue(langEntry, "Resource RVA could not be mapped to a file offset.");
            continue;
          }
          if (langEntry.size <= 0) continue;
          const data = new Uint8Array(
            await file
              .slice(dataOff, dataOff + langEntry.size)
              .arrayBuffer()
          );
          if (data.byteLength < langEntry.size) {
            addPreviewIssue(
              langEntry,
              "Resource preview read fewer bytes than the declared data size."
            );
          }
          const safePreview = (fn: () => void): void => {
            try {
              fn();
            } catch (err) {
              const msg = err instanceof Error ? err.message : String(err);
              addPreviewIssue(langEntry, `Preview failed: ${msg}`);
            }
          };
          safePreview(() => addIconPreview(langEntry, data, typeName));
          safePreview(() => addManifestPreview(langEntry, data, typeName, langEntry.codePage));
          safePreview(() => addHtmlPreview(langEntry, data, typeName, langEntry.codePage));
          safePreview(() => addVersionPreview(langEntry, data, typeName));
          safePreview(() => addStringTablePreview(langEntry, data, typeName, entry.id));
          truncateStringTablePreview(langEntry);
          if (typeName === "MESSAGETABLE") {
            const messageTable = decodeMessageTablePreview(data, langEntry.codePage);
            if (messageTable) {
              langEntry.previewKind = "messageTable";
              langEntry.messageTable = {
                messages: messageTable.messages,
                truncated: messageTable.truncated
              };
              if (messageTable.truncated) {
                addPreviewIssue(langEntry, "Message table preview is truncated or malformed.");
              }
              messageTable.issues.forEach(issue => addPreviewIssue(langEntry, issue));
            }
          }
          await addGroupIconPreview(
            file,
            langEntry,
            typeName,
            langEntry.dataRVA,
            langEntry.size,
            iconIndex,
            rvaToOff
          ).catch(err => {
            const msg = err instanceof Error ? err.message : String(err);
            addPreviewIssue(langEntry, `Icon group preview failed: ${msg}`);
          });
        } catch {
          addPreviewIssue(langEntry, "Resource bytes could not be read for preview.");
        }
      }
    }
  }

  return { top, detail, ...(issues.length ? { issues } : {}) };
}
