"use strict";

import type { FileRangeReader } from "../../../file-range-reader.js";
import { chooseResourceLeafRecord } from "./leaf-index.js";
import type { ResourceLeafIndex } from "./leaf-index.js";
import type { ResourceLangWithPreview } from "./types.js";
import type { LoadedResourceLeaf, LoadResourceLeafData } from "./icon.js";

export const createGroupLeafLoader = (
  reader: FileRangeReader,
  index: ResourceLeafIndex,
  groupTypeName: "GROUP_ICON" | "GROUP_CURSOR",
  leafTypeName: "ICON" | "CURSOR"
): LoadResourceLeafData => async (
  id: number,
  lang: number | null | undefined
): Promise<LoadedResourceLeaf> => {
  const record = chooseResourceLeafRecord(index, id, lang);
  if (!record) return { data: null };
  if (record.dataFileOffset == null || record.dataFileOffset < 0) {
    return {
      data: null,
      issues: [
        `${groupTypeName} references ${leafTypeName} leaf ID ${id}, but its RVA could not be mapped to a file offset.`
      ]
    };
  }
  if (record.size <= 0) {
    return {
      data: null,
      issues: [
        `${groupTypeName} references ${leafTypeName} leaf ID ${id}, but the leaf payload size is zero.`
      ]
    };
  }
  const data = await reader.readBytes(record.dataFileOffset, record.size);
  return {
    data: data.byteLength ? data : null,
    ...(data.byteLength < record.size
      ? {
          issues: [
            `${groupTypeName} references ${leafTypeName} leaf ID ${id}, but the leaf payload is truncated.`
          ]
        }
      : {})
  };
};

export const readResourceLeafBytes = async (
  reader: FileRangeReader,
  langEntry: ResourceLangWithPreview
): Promise<LoadedResourceLeaf> => {
  if (langEntry.dataFileOffset == null || langEntry.dataFileOffset < 0) {
    return {
      data: null,
      issues: ["Resource RVA could not be mapped to a file offset."]
    };
  }
  const data = await reader.readBytes(langEntry.dataFileOffset, langEntry.size);
  return {
    data: data.byteLength ? data : null,
    ...(data.byteLength < langEntry.size
      ? { issues: ["Resource preview read fewer bytes than the declared data size."] }
      : {})
  };
};
