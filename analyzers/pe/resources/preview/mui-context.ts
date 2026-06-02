"use strict";

import type { FileRangeReader } from "../../../file-range-reader.js";
import {
  parseMuiResourceConfigurationDetailed,
  type MuiResourceConfigurationParseResult
} from "../mui-config.js";
import type { ResourceTree } from "../tree-types.js";
import { readResourceLeafBytes } from "./leaf-data.js";
import type {
  ResourceDetailGroup,
  ResourceLangWithPreview
} from "./types.js";

export interface MuiResourceContext {
  dataRVA: number;
  size: number;
  result: MuiResourceConfigurationParseResult;
}

const findMuiResourceConfigurationLang = (
  detail: ResourceDetailGroup[]
): ResourceLangWithPreview | null =>
  detail.find(group => group.typeName === "MUI")
    ?.entries.find(entry => entry.id === 1)
    ?.langs[0] ?? null;

export const readMuiResourceContext = async (
  reader: FileRangeReader,
  tree: ResourceTree,
  detail: ResourceDetailGroup[]
): Promise<MuiResourceContext | null> => {
  const langEntry = findMuiResourceConfigurationLang(detail);
  if (!langEntry?.size || !langEntry.dataRVA) return null;
  const leaf = await readResourceLeafBytes(reader, tree, langEntry);
  const result = leaf.data
    ? parseMuiResourceConfigurationDetailed(leaf.data)
    : { configuration: null, issues: [] };
  return {
    dataRVA: langEntry.dataRVA,
    size: langEntry.size,
    result: {
      configuration: result.configuration,
      issues: [...(leaf.issues || []), ...result.issues]
    }
  };
};
