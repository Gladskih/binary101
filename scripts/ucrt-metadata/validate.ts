"use strict";

import { readFile } from "node:fs/promises";
import { join } from "node:path";
import {
  isUcrtMetadataChunk,
  isUcrtMetadataManifest,
  type UcrtMetadataChunk,
  type UcrtMetadataManifest
} from "../../ucrt-metadata-schema.js";
import { UCRT_METADATA_OUTPUT_DIR } from "./config.js";

const parseJson = (text: string): unknown => JSON.parse(text) as unknown;

const readJson = async (path: string): Promise<unknown> =>
  parseJson(await readFile(path, "utf8"));

const readManifest = async (): Promise<UcrtMetadataManifest> => {
  const manifest = await readJson(join(UCRT_METADATA_OUTPUT_DIR, "manifest.json"));
  if (!isUcrtMetadataManifest(manifest)) {
    throw new Error("UCRT metadata manifest.json does not match the expected shape.");
  }
  return manifest;
};

const readChunk = async (path: string): Promise<UcrtMetadataChunk> => {
  const chunk = await readJson(join(UCRT_METADATA_OUTPUT_DIR, path));
  if (!isUcrtMetadataChunk(chunk)) {
    throw new Error(`UCRT metadata chunk ${path} does not match the expected shape.`);
  }
  return chunk;
};

const validateChunk = (chunk: UcrtMetadataChunk): number => {
  const entryCount = Object.keys(chunk.entries).length;
  if (entryCount !== chunk.entryCount) {
    throw new Error(`UCRT metadata chunk ${chunk.dll} has an incorrect entry count.`);
  }
  return entryCount;
};

const validateManifestCounts = (
  manifest: UcrtMetadataManifest,
  chunks: UcrtMetadataChunk[]
): void => {
  const totalEntries = chunks.reduce((total, chunk) => total + validateChunk(chunk), 0);
  if (chunks.length !== manifest.entryCounts.dlls) {
    throw new Error("UCRT metadata manifest DLL count does not match chunk count.");
  }
  if (totalEntries !== manifest.entryCounts.entries) {
    throw new Error("UCRT metadata manifest entry count does not match chunk entries.");
  }
};

const main = async (): Promise<void> => {
  const manifest = await readManifest();
  const chunks = await Promise.all(manifest.chunks.map(chunk => readChunk(chunk.path)));
  validateManifestCounts(manifest, chunks);
  console.warn(
    `Validated UCRT metadata: ${manifest.entryCounts.entries} entries ` +
    `across ${manifest.entryCounts.dlls} DLL chunks.`
  );
};

void main();
