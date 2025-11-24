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

export async function enrichResourcePreviews(
  file: File,
  tree: ResourceTree
): Promise<{ top: ResourceTree["top"]; detail: ResourceDetailGroup[] }> {
  const { base, limitEnd, top, view, rvaToOff } = tree;
  const detail = tree.detail as ResourceDetailGroup[];
  const isInside = (off: number): boolean => off >= base && off < limitEnd;

  const iconIndex = new Map<number, { rva: number; size: number }>();
  const rootDirView = await view(base, 16);
  const NamedRoot = rootDirView.getUint16(12, true);
  const IdsRoot = rootDirView.getUint16(14, true);
  const countRoot = NamedRoot + IdsRoot;
  for (let index = 0; index < countRoot; index += 1) {
    const e = await view(base + 16 + index * 8, 8);
    const Name = e.getUint32(0, true);
    const OffsetToData = e.getUint32(4, true);
    const subdir = (OffsetToData & 0x80000000) !== 0;
    const id = (Name & 0x80000000) ? null : (Name & 0xffff);
    if (id !== 3 || !subdir) continue;
    const nameDirRel = OffsetToData & 0x7fffffff;
    const nameDirOff = base + nameDirRel;
    if (!isInside(nameDirOff + 16)) continue;
    const nameDirView = await view(nameDirOff, 16);
    const Named = nameDirView.getUint16(12, true);
    const Ids = nameDirView.getUint16(14, true);
    const count = Named + Ids;
    for (let idx = 0; idx < count; idx += 1) {
      const e2 = await view(nameDirOff + 16 + idx * 8, 8);
      const Name2 = e2.getUint32(0, true);
      const OffsetToData2 = e2.getUint32(4, true);
      const subdir2 = (OffsetToData2 & 0x80000000) !== 0;
      const id2 = (Name2 & 0x80000000) ? null : (Name2 & 0xffff);
      if (!subdir2) continue;
      const langDirRel = OffsetToData2 & 0x7fffffff;
      const langDirOff = base + langDirRel;
      if (!isInside(langDirOff + 16)) continue;
      const langDirView = await view(langDirOff, 16);
      const NamedL = langDirView.getUint16(12, true);
      const IdsL = langDirView.getUint16(14, true);
      const countL = NamedL + IdsL;
      for (let j = 0; j < countL; j += 1) {
        const le = await view(langDirOff + 16 + j * 8, 8);
        const OffsetToDataL = le.getUint32(4, true);
        const subdirL = (OffsetToDataL & 0x80000000) !== 0;
        if (subdirL) continue;
        const dataRel = OffsetToDataL & 0x7fffffff;
        const deo2 = base + dataRel;
        if (!isInside(deo2 + 16)) continue;
        const dv2 = await view(deo2, 16);
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
            await file.slice(dataOff, dataOff + Math.min(langEntry.size, 262144)).arrayBuffer()
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
