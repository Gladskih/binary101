"use strict";

import type { FileRangeReader } from "../../../file-range-reader.js";
import {
  parseMuiResourceConfigurationDetailed,
  type MuiResourceConfigurationParseResult
} from "../mui-config.js";
import { readResourceLeafBytes } from "./leaf-data.js";
import type {
  ResourceDetailGroup,
  ResourceLangWithPreview
} from "./types.js";

export interface MuiResourceCandidate {
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
  langEntry: ResourceLangWithPreview
): Promise<MuiResourceCandidate | null> => {
  if (!langEntry.size || !langEntry.dataRVA) return null;
  const leaf = await readResourceLeafBytes(reader, langEntry);
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

export const readMuiResource = async (
  reader: FileRangeReader,
  detail: ResourceDetailGroup[]
): Promise<MuiResourceCandidate | null> => {
  let firstParsedCandidate: MuiResourceCandidate | null = null;
  for (const langEntry of findMuiResourceConfigurationLangs(detail)) {
    const candidate = await readMuiResourceCandidate(reader, langEntry);
    if (!candidate) continue;
    if (candidate.result.configuration) return candidate;
    firstParsedCandidate ??= candidate;
  }
  return firstParsedCandidate;
};
