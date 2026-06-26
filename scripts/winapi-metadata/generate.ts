"use strict";

import { mkdir, readdir, unlink, writeFile } from "node:fs/promises";
import { join } from "node:path";
import type {
  WinapiMetadataChunk,
  WinapiMetadataEntrypointIndex,
  WinapiMetadataManifest
} from "../../winapi-metadata-schema.js";
import { WINAPI_METADATA_OUTPUT_DIR } from "./config.js";
import { readWinmdFromNugetPackage } from "./nuget-package.js";
import {
  WINAPI_METADATA_ENTRYPOINT_INDEX_PATH,
  buildWinapiMetadataAssets,
  chunkOutputName
} from "./winmd-assets.js";

const json = (
  value: WinapiMetadataChunk | WinapiMetadataEntrypointIndex | WinapiMetadataManifest
): string =>
  JSON.stringify(value);

const clearGeneratedJson = async (): Promise<void> => {
  await mkdir(WINAPI_METADATA_OUTPUT_DIR, { recursive: true });
  const entries = await readdir(WINAPI_METADATA_OUTPUT_DIR, { withFileTypes: true });
  await Promise.all(entries
    .filter(entry => entry.isFile() && entry.name.endsWith(".json"))
    .map(entry => unlink(join(WINAPI_METADATA_OUTPUT_DIR, entry.name))));
};

const writeGeneratedAssets = async (
  manifest: WinapiMetadataManifest,
  chunks: WinapiMetadataChunk[],
  entrypointIndex: WinapiMetadataEntrypointIndex
): Promise<void> => {
  await clearGeneratedJson();
  await writeFile(join(WINAPI_METADATA_OUTPUT_DIR, "manifest.json"), json(manifest));
  await writeFile(
    join(WINAPI_METADATA_OUTPUT_DIR, WINAPI_METADATA_ENTRYPOINT_INDEX_PATH),
    json(entrypointIndex)
  );
  await Promise.all(chunks.map(chunk =>
    writeFile(join(WINAPI_METADATA_OUTPUT_DIR, chunkOutputName(chunk)), json(chunk))));
};

const main = async (): Promise<void> => {
  const generatedAt = new Date().toISOString();
  const assets = await buildWinapiMetadataAssets(await readWinmdFromNugetPackage(), generatedAt);
  await writeGeneratedAssets(assets.manifest, assets.chunks, assets.entrypointIndex);
  console.warn(
    `Generated WinAPI metadata: ${assets.manifest.entryCounts.entries} entries ` +
    `across ${assets.manifest.entryCounts.dlls} DLL chunks.`
  );
};

void main();
