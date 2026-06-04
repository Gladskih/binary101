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

const findMuiResourceConfigurationLangs = (
  detail: ResourceDetailGroup[]
): ResourceLangWithPreview[] =>
  detail
    .filter(group => group.typeName === "MUI")
    .flatMap(group => group.entries.flatMap(entry => entry.langs as ResourceLangWithPreview[]));

const readMuiResourceCandidate = async (
  reader: FileRangeReader,
  tree: ResourceTree,
  langEntry: ResourceLangWithPreview
): Promise<MuiResourceContext | null> => {
  if (!langEntry.size || !langEntry.dataRVA) return null;
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

export const readMuiResourceContext = async (
  reader: FileRangeReader,
  tree: ResourceTree,
  detail: ResourceDetailGroup[]
): Promise<MuiResourceContext | null> => {
  let firstParsedCandidate: MuiResourceContext | null = null;
  for (const langEntry of findMuiResourceConfigurationLangs(detail)) {
    const context = await readMuiResourceCandidate(reader, tree, langEntry);
    if (!context) continue;
    if (context.result.configuration) return context;
    firstParsedCandidate ??= context;
  }
  return firstParsedCandidate;
};
