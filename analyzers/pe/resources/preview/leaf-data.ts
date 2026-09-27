"use strict";

import type { ResourcePayloadReader } from "../payload-reader.js";
import { chooseResourceLeafRecord } from "./leaf-index.js";
import type { ResourceLeafIndex } from "./leaf-index.js";
import type { ResourceLangWithPreview } from "./types.js";
import type { LoadedResourceLeaf, LoadResourceLeafData } from "./icon.js";

export const createGroupLeafLoader = (
  reader: ResourcePayloadReader,
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
  const data = reader.readResourceBytes && record.dataRVA != null
    ? await reader.readResourceBytes(record.dataRVA, record.size)
    : await reader.readBytes(record.dataFileOffset, record.size);
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

const readLeafPayload = (
  reader: ResourcePayloadReader, rva: number, offset: number, size: number
): Promise<Uint8Array> => reader.readResourceBytes
  ? reader.readResourceBytes(rva, size) : reader.readBytes(offset, size);

export const readResourceLeafBytes = async (
  reader: ResourcePayloadReader,
  langEntry: ResourceLangWithPreview
): Promise<LoadedResourceLeaf> => {
  if (langEntry.dataFileOffset == null || langEntry.dataFileOffset < 0) {
    return {
      data: null,
      issues: ["Resource RVA could not be mapped to a file offset."]
    };
  }
  if (!Number.isSafeInteger(langEntry.size) || langEntry.size < 0) {
    return { data: null, issues: ["Resource preview has an invalid size."] };
  }
  const issues: string[] = [];
  const data = await readLeafPayload(reader, langEntry.dataRVA, langEntry.dataFileOffset, langEntry.size);
  if (data.byteLength < langEntry.size) {
    issues.push("Resource preview read fewer bytes than the declared data size.");
  }
  return {
    data: data.byteLength ? data : null,
    ...(issues.length ? { issues } : {})
  };
};
