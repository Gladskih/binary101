"use strict";

import type { FileRangeReader } from "../../../file-range-reader.js";
import {
  parseMuiResourceConfiguration,
  type MuiResourceConfiguration
} from "../mui-config.js";
import type { ResourceTree } from "../tree-types.js";
import { readResourceLeafBytes } from "./leaf-data.js";
import type {
  ResourceDetailGroup,
  ResourceLangWithPreview
} from "./types.js";

const findMuiResourceConfigurationLang = (
  detail: ResourceDetailGroup[]
): ResourceLangWithPreview | null =>
  detail.find(group => group.typeName === "MUI")
    ?.entries.find(entry => entry.id === 1)
    ?.langs[0] ?? null;

export const readMuiResourceConfiguration = async (
  reader: FileRangeReader,
  tree: ResourceTree,
  detail: ResourceDetailGroup[]
): Promise<MuiResourceConfiguration | null> => {
  const langEntry = findMuiResourceConfigurationLang(detail);
  if (!langEntry?.size || !langEntry.dataRVA) return null;
  const leaf = await readResourceLeafBytes(reader, tree, langEntry);
  return leaf.data ? parseMuiResourceConfiguration(leaf.data) : null;
};
