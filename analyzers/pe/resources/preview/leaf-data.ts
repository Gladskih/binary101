"use strict";

import type { FileRangeReader } from "../../../file-range-reader.js";
import { chooseResourceLeafRecord } from "./leaf-index.js";
import type { ResourceLeafIndex } from "./leaf-index.js";
import type { ResourceLangWithPreview } from "./types.js";
import type { ResourceTree } from "../core.js";
import type { LoadedResourceLeaf, LoadResourceLeafData } from "./icon.js";

export const createGroupLeafLoader = (
  reader: FileRangeReader,
  tree: ResourceTree,
  index: ResourceLeafIndex,
  groupTypeName: "GROUP_ICON" | "GROUP_CURSOR",
  leafTypeName: "ICON" | "CURSOR"
): LoadResourceLeafData => async (
  id: number,
  lang: number | null | undefined
): Promise<LoadedResourceLeaf> => {
  const record = chooseResourceLeafRecord(index, id, lang);
  if (!record) return { data: null };
  const offset = tree.rvaToOff(record.dataRva);
  if (offset == null || offset < 0) {
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
  const data = await reader.readBytes(offset, record.size);
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
  tree: ResourceTree,
  langEntry: ResourceLangWithPreview
): Promise<LoadedResourceLeaf> => {
  const offset = tree.rvaToOff(langEntry.dataRVA);
  if (offset == null) {
    return {
      data: null,
      issues: ["Resource RVA could not be mapped to a file offset."]
    };
  }
  const data = await reader.readBytes(offset, langEntry.size);
  return {
    data: data.byteLength ? data : null,
    ...(data.byteLength < langEntry.size
      ? { issues: ["Resource preview read fewer bytes than the declared data size."] }
      : {})
  };
};
