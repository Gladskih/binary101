"use strict";

import type { FileRangeReader } from "../../file-range-reader.js";
import { buildResourceTree } from "./core.js";
import { enrichResourcePreviews } from "./preview/index.js";
import {
  parseBrowserManifestXmlDocument,
  type ManifestXmlDocumentParser
} from "./preview/manifest-xml.js";
import type { ResourceDetailGroup } from "./preview/types.js";
import type { ResourceTree } from "./tree-types.js";
import type { PeDataDirectory, RvaToOffset } from "../types.js";

export interface PeResources {
  top: ResourceTree["top"];
  detail: ResourceDetailGroup[];
  directories?: ResourceTree["directories"];
  paths?: ResourceTree["paths"];
  issues?: string[];
}

export async function parseResources(
  reader: FileRangeReader,
  dataDirs: PeDataDirectory[],
  rvaToOff: RvaToOffset,
  parseManifestXmlDocument: ManifestXmlDocumentParser = parseBrowserManifestXmlDocument
): Promise<PeResources | null> {
  const tree = await buildResourceTree(reader, dataDirs, rvaToOff);
  if (!tree) return null;
  return enrichResourcePreviews(reader, tree, parseManifestXmlDocument);
}
