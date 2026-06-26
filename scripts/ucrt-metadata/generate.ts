"use strict";

import { mkdir, readdir, unlink, writeFile } from "node:fs/promises";
import { join } from "node:path";
import type { UcrtMetadataChunk, UcrtMetadataManifest } from "../../ucrt-metadata-schema.js";
import { UCRT_METADATA_OUTPUT_DIR } from "./config.js";
import { readUcrtHeaderPackage, readUcrtImportLibrary } from "./nuget-package.js";
import { buildUcrtMetadataAssets, chunkOutputName } from "./ucrt-assets.js";

const json = (value: UcrtMetadataChunk | UcrtMetadataManifest): string =>
  JSON.stringify(value);

const clearGeneratedJson = async (): Promise<void> => {
  await mkdir(UCRT_METADATA_OUTPUT_DIR, { recursive: true });
  const entries = await readdir(UCRT_METADATA_OUTPUT_DIR, { withFileTypes: true });
  await Promise.all(entries
    .filter(entry => entry.isFile() && entry.name.endsWith(".json"))
    .map(entry => unlink(join(UCRT_METADATA_OUTPUT_DIR, entry.name))));
};

const writeGeneratedAssets = async (
  manifest: UcrtMetadataManifest,
  chunks: UcrtMetadataChunk[]
): Promise<void> => {
  await clearGeneratedJson();
  await writeFile(join(UCRT_METADATA_OUTPUT_DIR, "manifest.json"), json(manifest));
  await Promise.all(chunks.map(chunk =>
    writeFile(join(UCRT_METADATA_OUTPUT_DIR, chunkOutputName(chunk)), json(chunk))));
};

const main = async (): Promise<void> => {
  const generatedAt = new Date().toISOString();
  const assets = await buildUcrtMetadataAssets(
    await readUcrtHeaderPackage(),
    await readUcrtImportLibrary(),
    generatedAt
  );
  await writeGeneratedAssets(assets.manifest, assets.chunks);
  console.warn(
    `Generated UCRT metadata: ${assets.manifest.entryCounts.entries} entries ` +
    `across ${assets.manifest.entryCounts.dlls} DLL chunks.`
  );
};

void main();
