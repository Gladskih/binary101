"use strict";

import { readFile } from "node:fs/promises";
import { join } from "node:path";
import {
  isWinapiMetadataChunk,
  isWinapiMetadataEntrypointIndex,
  isWinapiMetadataManifest,
  type WinapiMetadataChunk,
  type WinapiMetadataEntrypointIndex,
  type WinapiMetadataManifest
} from "../../winapi-metadata-schema.js";
import { WINAPI_METADATA_OUTPUT_DIR } from "./config.js";

const parseJson = (text: string): unknown => JSON.parse(text) as unknown;

const readJson = async (path: string): Promise<unknown> =>
  parseJson(await readFile(path, "utf8"));

const readManifest = async (): Promise<WinapiMetadataManifest> => {
  const manifest = await readJson(join(WINAPI_METADATA_OUTPUT_DIR, "manifest.json"));
  if (!isWinapiMetadataManifest(manifest)) {
    throw new Error("WinAPI metadata manifest.json does not match the expected shape.");
  }
  return manifest;
};

const readChunk = async (path: string): Promise<WinapiMetadataChunk> => {
  const chunk = await readJson(join(WINAPI_METADATA_OUTPUT_DIR, path));
  if (!isWinapiMetadataChunk(chunk)) {
    throw new Error(`WinAPI metadata chunk ${path} does not match the expected shape.`);
  }
  return chunk;
};

const readEntrypointIndex = async (path: string): Promise<WinapiMetadataEntrypointIndex> => {
  const entrypointIndex = await readJson(join(WINAPI_METADATA_OUTPUT_DIR, path));
  if (!isWinapiMetadataEntrypointIndex(entrypointIndex)) {
    throw new Error(`WinAPI metadata entrypoint index ${path} does not match the expected shape.`);
  }
  return entrypointIndex;
};

const validateChunk = (chunk: WinapiMetadataChunk): number => {
  const entryCount = Object.keys(chunk.entries).length;
  if (entryCount !== chunk.entryCount) {
    throw new Error(`WinAPI metadata chunk ${chunk.dll} has an incorrect entry count.`);
  }
  return entryCount;
};

const validateEntrypointIndex = (
  manifest: WinapiMetadataManifest,
  entrypointIndex: WinapiMetadataEntrypointIndex
): void => {
  const entryCount = Object.keys(entrypointIndex.entries).length;
  const referenceCount = Object.values(entrypointIndex.entries)
    .reduce((total, moduleKeys) => total + moduleKeys.length, 0);
  if (entryCount !== manifest.entrypointIndex.entries) {
    throw new Error("WinAPI metadata entrypoint-index entry count does not match manifest.");
  }
  if (referenceCount !== manifest.entrypointIndex.references) {
    throw new Error("WinAPI metadata entrypoint-index reference count does not match manifest.");
  }
};

const validateManifestCounts = (
  manifest: WinapiMetadataManifest,
  chunks: WinapiMetadataChunk[]
): void => {
  const totalEntries = chunks.reduce((total, chunk) => total + validateChunk(chunk), 0);
  if (chunks.length !== manifest.entryCounts.dlls) {
    throw new Error("WinAPI metadata manifest DLL count does not match chunk count.");
  }
  if (totalEntries !== manifest.entryCounts.entries) {
    throw new Error("WinAPI metadata manifest entry count does not match chunk entries.");
  }
};

const main = async (): Promise<void> => {
  const manifest = await readManifest();
  const [entrypointIndex, chunks] = await Promise.all([
    readEntrypointIndex(manifest.entrypointIndex.path),
    Promise.all(manifest.chunks.map(chunk => readChunk(chunk.path)))
  ]);
  validateManifestCounts(manifest, chunks);
  validateEntrypointIndex(manifest, entrypointIndex);
  console.warn(
    `Validated WinAPI metadata: ${manifest.entryCounts.entries} entries ` +
    `across ${manifest.entryCounts.dlls} DLL chunks.`
  );
};

void main();
