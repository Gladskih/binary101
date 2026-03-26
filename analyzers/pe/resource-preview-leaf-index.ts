"use strict";

import type { ResourceDetailGroup, ResourceLangWithPreview } from "./resources-preview-types.js";

export interface ResourceLeafRecord {
  lang: number | null;
  dataRva: number;
  size: number;
}

export type ResourceLeafIndex = Map<number, ResourceLeafRecord[]>;

export const buildResourceLeafIndex = (
  detail: ResourceDetailGroup[],
  typeName: string
): ResourceLeafIndex => {
  const index = new Map<number, ResourceLeafRecord[]>();
  const group = detail.find(entry => entry.typeName === typeName);
  if (!group) return index;
  for (const entry of group.entries) {
    if (entry.id == null) continue;
    const records: ResourceLeafRecord[] = [];
    for (const langEntry of entry.langs as ResourceLangWithPreview[]) {
      if (!langEntry.dataRVA || !langEntry.size) continue;
      records.push({
        lang: langEntry.lang ?? null,
        dataRva: langEntry.dataRVA,
        size: langEntry.size
      });
    }
    if (records.length) index.set(entry.id, records);
  }
  return index;
};

export const chooseResourceLeafRecord = (
  index: ResourceLeafIndex,
  id: number,
  lang: number | null | undefined
): ResourceLeafRecord | null => {
  const records = index.get(id);
  if (!records?.length) return null;
  const exact = records.find(record => record.lang === (lang ?? null));
  return exact || records[0] || null;
};
