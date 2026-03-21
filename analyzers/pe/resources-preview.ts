"use strict";

import { addIconPreview, addGroupIconPreview } from "./resources-preview-icon.js";
import {
  addHtmlPreview,
  addManifestPreview,
  addMessageTablePreview,
  addPreviewIssue,
  addStringTablePreview,
  addVersionPreview
} from "./resources-preview-text.js";
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
// winnt.h: MESSAGE_RESOURCE_BLOCK stores LowId, HighId, OffsetToEntries as three DWORDs.
const MESSAGE_BLOCK_HEADER_SIZE = 12;
// winnt.h: MESSAGE_RESOURCE_ENTRY starts with WORD Length and WORD Flags.
const MESSAGE_ENTRY_HEADER_SIZE = 4;
// winnt.h: MESSAGE_RESOURCE_UNICODE marks UTF-16LE entry text.
const MESSAGE_RESOURCE_UNICODE_FLAG = 0x0001;

const truncateStringTablePreview = (langEntry: ResourceLangWithPreview): void => {
  if (langEntry.previewKind !== "stringTable") return;
  if (langEntry.stringPreview?.length && langEntry.stringPreview.length > STRING_TABLE_ENTRY_COUNT) {
    langEntry.stringPreview = langEntry.stringPreview.slice(0, STRING_TABLE_ENTRY_COUNT);
  }
  if (langEntry.stringTable?.length && langEntry.stringTable.length > STRING_TABLE_ENTRY_COUNT) {
    langEntry.stringTable = langEntry.stringTable.slice(0, STRING_TABLE_ENTRY_COUNT);
  }
};

const decodeMessageEntryText = (entryBytes: Uint8Array, isUnicode: boolean): string => {
  if (!entryBytes.length) return "";
  if (isUnicode) {
    let text = "";
    for (let index = 0; index + 1 < entryBytes.length; index += 2) {
      const first = entryBytes[index];
      const second = entryBytes[index + 1];
      if (first === undefined || second === undefined) break;
      const code = first | (second << 8);
      if (code === 0) break;
      text += String.fromCharCode(code);
    }
    return text.trim();
  }
  const zeroIndex = entryBytes.indexOf(0);
  const slice = zeroIndex === -1 ? entryBytes : entryBytes.slice(0, zeroIndex);
  return new TextDecoder("utf-8", { fatal: false }).decode(slice).trim();
};

const decodeMessageTablePreview = (
  data: Uint8Array
): { messages: Array<{ id: number; strings: string[] }>; truncated: boolean } | null => {
  if (data.byteLength < 4) return null;
  const dv = new DataView(data.buffer, data.byteOffset, data.byteLength);
  const blockCount = dv.getUint32(0, true);
  const maxBlocks = Math.min(blockCount, Math.floor((data.byteLength - 4) / MESSAGE_BLOCK_HEADER_SIZE));
  const messages: Array<{ id: number; strings: string[] }> = [];
  let truncated = maxBlocks < blockCount;
  for (let blockIndex = 0; blockIndex < maxBlocks; blockIndex += 1) {
    const blockOff = 4 + blockIndex * MESSAGE_BLOCK_HEADER_SIZE;
    if (blockOff + MESSAGE_BLOCK_HEADER_SIZE > data.byteLength) {
      truncated = true;
      break;
    }
    const lowId = dv.getUint32(blockOff, true);
    const highId = dv.getUint32(blockOff + 4, true);
    const entryOffset = dv.getUint32(blockOff + 8, true);
    if (highId < lowId || entryOffset >= data.byteLength) {
      truncated = true;
      continue;
    }
    const blockEnd = blockIndex + 1 < maxBlocks
      ? Math.min(data.byteLength, dv.getUint32(4 + (blockIndex + 1) * MESSAGE_BLOCK_HEADER_SIZE + 8, true))
      : data.byteLength;
    const entryCount = highId - lowId + 1;
    const strings: string[] = [];
    let pos = entryOffset;
    for (let entryIndex = 0; entryIndex < entryCount; entryIndex += 1) {
      if (pos + MESSAGE_ENTRY_HEADER_SIZE > blockEnd) {
        truncated = true;
        break;
      }
      const length = dv.getUint16(pos, true);
      const flags = dv.getUint16(pos + 2, true);
      if (length < MESSAGE_ENTRY_HEADER_SIZE || pos + length > blockEnd) {
        truncated = true;
        break;
      }
      const entryBytes = data.subarray(pos + MESSAGE_ENTRY_HEADER_SIZE, pos + length);
      strings.push(decodeMessageEntryText(entryBytes, (flags & MESSAGE_RESOURCE_UNICODE_FLAG) !== 0));
      pos += length;
    }
    messages.push({ id: lowId, strings });
  }
  return { messages, truncated };
};

export async function enrichResourcePreviews(
  file: File,
  tree: ResourceTree
): Promise<{ top: ResourceTree["top"]; detail: ResourceDetailGroup[] }> {
  const { base, limitEnd, top, view, rvaToOff } = tree;
  const detail = tree.detail as ResourceDetailGroup[];
  const isRangeInside = (off: number, len: number): boolean =>
    off >= base && len >= 0 && off + len <= limitEnd;

  const iconIndex = new Map<number, { rva: number; size: number }>();
  const rootDirView = await view(base, RESOURCE_DIRECTORY_HEADER_SIZE);
  if (rootDirView.byteLength < RESOURCE_DIRECTORY_HEADER_SIZE) return { top, detail };
  const NamedRoot = rootDirView.getUint16(RESOURCE_DIRECTORY_HEADER_SIZE - 4, true);
  const IdsRoot = rootDirView.getUint16(RESOURCE_DIRECTORY_HEADER_SIZE - 2, true);
  const countRoot = NamedRoot + IdsRoot;
  for (let index = 0; index < countRoot; index += 1) {
    const e = await view(
      base + RESOURCE_DIRECTORY_HEADER_SIZE + index * RESOURCE_DIRECTORY_ENTRY_SIZE,
      RESOURCE_DIRECTORY_ENTRY_SIZE
    );
    if (e.byteLength < RESOURCE_DIRECTORY_ENTRY_SIZE) break;
    const Name = e.getUint32(0, true);
    const OffsetToData = e.getUint32(4, true);
    const subdir = (OffsetToData & RESOURCE_DIRECTORY_FLAG_MASK) !== 0;
    const id = (Name & RESOURCE_DIRECTORY_FLAG_MASK) ? null : (Name & RESOURCE_INTEGER_ID_MASK);
    if (id !== 3 /* RT_ICON */ || !subdir) continue;
    const nameDirRel = OffsetToData & RESOURCE_DIRECTORY_OFFSET_MASK;
    const nameDirOff = base + nameDirRel;
    if (!isRangeInside(nameDirOff, RESOURCE_DIRECTORY_HEADER_SIZE)) continue;
    const nameDirView = await view(nameDirOff, RESOURCE_DIRECTORY_HEADER_SIZE);
    if (nameDirView.byteLength < RESOURCE_DIRECTORY_HEADER_SIZE) continue;
    const Named = nameDirView.getUint16(RESOURCE_DIRECTORY_HEADER_SIZE - 4, true);
    const Ids = nameDirView.getUint16(RESOURCE_DIRECTORY_HEADER_SIZE - 2, true);
    const count = Named + Ids;
    for (let idx = 0; idx < count; idx += 1) {
      const e2 = await view(
        nameDirOff + RESOURCE_DIRECTORY_HEADER_SIZE + idx * RESOURCE_DIRECTORY_ENTRY_SIZE,
        RESOURCE_DIRECTORY_ENTRY_SIZE
      );
      if (e2.byteLength < RESOURCE_DIRECTORY_ENTRY_SIZE) break;
      const Name2 = e2.getUint32(0, true);
      const OffsetToData2 = e2.getUint32(4, true);
      const subdir2 = (OffsetToData2 & RESOURCE_DIRECTORY_FLAG_MASK) !== 0;
      const id2 = (Name2 & RESOURCE_DIRECTORY_FLAG_MASK) ? null : (Name2 & RESOURCE_INTEGER_ID_MASK);
      if (!subdir2) continue;
      const langDirRel = OffsetToData2 & RESOURCE_DIRECTORY_OFFSET_MASK;
      const langDirOff = base + langDirRel;
      if (!isRangeInside(langDirOff, RESOURCE_DIRECTORY_HEADER_SIZE)) continue;
      const langDirView = await view(langDirOff, RESOURCE_DIRECTORY_HEADER_SIZE);
      if (langDirView.byteLength < RESOURCE_DIRECTORY_HEADER_SIZE) continue;
      const NamedL = langDirView.getUint16(RESOURCE_DIRECTORY_HEADER_SIZE - 4, true);
      const IdsL = langDirView.getUint16(RESOURCE_DIRECTORY_HEADER_SIZE - 2, true);
      const countL = NamedL + IdsL;
      for (let j = 0; j < countL; j += 1) {
        const le = await view(
          langDirOff + RESOURCE_DIRECTORY_HEADER_SIZE + j * RESOURCE_DIRECTORY_ENTRY_SIZE,
          RESOURCE_DIRECTORY_ENTRY_SIZE
        );
        if (le.byteLength < RESOURCE_DIRECTORY_ENTRY_SIZE) break;
        const OffsetToDataL = le.getUint32(4, true);
        const subdirL = (OffsetToDataL & RESOURCE_DIRECTORY_FLAG_MASK) !== 0;
        if (subdirL) continue;
        const dataRel = OffsetToDataL & RESOURCE_DIRECTORY_OFFSET_MASK;
        const deo2 = base + dataRel;
        if (!isRangeInside(deo2, RESOURCE_DIRECTORY_HEADER_SIZE)) continue;
        const dv2 = await view(deo2, RESOURCE_DIRECTORY_HEADER_SIZE);
        if (dv2.byteLength < 8) continue;
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
          if (dataOff == null || langEntry.size <= 0) continue;
          const data = new Uint8Array(
            await file
              // Parser policy: cap preview reads at 256 KiB so malformed resources cannot force
              // unbounded UI reads while still giving the preview code enough data to inspect.
              .slice(dataOff, dataOff + Math.min(langEntry.size, 256 * 1024))
              .arrayBuffer()
          );
          const safePreview = (fn: () => void): void => {
            try {
              fn();
            } catch (err) {
              const msg = err instanceof Error ? err.message : String(err);
              addPreviewIssue(langEntry, `Preview failed: ${msg}`);
            }
          };
          safePreview(() => addIconPreview(langEntry, data, typeName));
          safePreview(() => addManifestPreview(langEntry, data, typeName));
          safePreview(() => addHtmlPreview(langEntry, data, typeName));
          safePreview(() => addVersionPreview(langEntry, data, typeName));
          safePreview(() => addStringTablePreview(langEntry, data, typeName, entry.id));
          safePreview(() => addMessageTablePreview(langEntry, data, typeName));
          truncateStringTablePreview(langEntry);
          if (typeName === "MESSAGETABLE") {
            const messageTable = decodeMessageTablePreview(data);
            if (messageTable) {
              langEntry.previewKind = "messageTable";
              langEntry.messageTable = messageTable;
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

  return { top, detail };
}
