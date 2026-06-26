"use strict";

import type {
  UcrtMetadataChunk,
  UcrtMetadataEntry,
  UcrtMetadataManifest,
  UcrtMetadataManifestChunk,
  UcrtMetadataSource
} from "../../ucrt-metadata-schema.js";
import { UCRT_METADATA_FORMAT_VERSION } from "../../ucrt-metadata-schema.js";
import { UCRT_METADATA_PACKAGES } from "./config.js";
import { parseClangFunctions, type ClangFunctionDecl } from "./clang-ast.js";
import { extractHeaderWorkspace, runClangAstDump } from "./clang-workspace.js";
import { readCoffImportLibraryEntries, type CoffImportEntry } from "./coff-import-library.js";
import { createUcrtEntry } from "./signature-format.js";

const UCRTBASE_DLL = "ucrtbase.dll";

type DllEntries = Map<string, UcrtMetadataEntry>;

const sourceMetadata = (): UcrtMetadataSource => ({
  headerPackageName: UCRT_METADATA_PACKAGES.headers.name,
  importLibraryPackageName: UCRT_METADATA_PACKAGES.importLibrary.name,
  packageVersion: UCRT_METADATA_PACKAGES.headers.version,
  headerRoot: UCRT_METADATA_PACKAGES.headers.ucrtHeaderRoot,
  importLibraryPath: UCRT_METADATA_PACKAGES.importLibrary.path,
  architecture: UCRT_METADATA_PACKAGES.importLibrary.architecture
});

const moduleKey = (moduleName: string): string =>
  moduleName.trim().toLowerCase();

const chunkFileName = (moduleName: string): string =>
  `${moduleKey(moduleName).replaceAll(/[^a-z0-9._-]/g, "_")}.json`;

const addEntry = (
  entriesByDll: Map<string, DllEntries>,
  entry: UcrtMetadataEntry
): void => {
  const key = moduleKey(entry.module);
  const entries = entriesByDll.get(key) ?? new Map<string, UcrtMetadataEntry>();
  entries.set(entry.entrypoint, entry);
  entriesByDll.set(key, entries);
};

const buildEntriesByDll = (
  importEntries: CoffImportEntry[],
  functions: ReadonlyMap<string, ClangFunctionDecl>
): Map<string, DllEntries> => {
  const entriesByDll = new Map<string, DllEntries>();
  const aggregate = new Map<string, UcrtMetadataEntry>();
  for (const imported of importEntries) {
    const declaration = functions.get(imported.exportName);
    if (!declaration) continue;
    addEntry(entriesByDll, createUcrtEntry(imported.module, imported.exportName, declaration));
    aggregate.set(imported.exportName, createUcrtEntry(UCRTBASE_DLL, imported.exportName, declaration));
  }
  if (aggregate.size) entriesByDll.set(moduleKey(UCRTBASE_DLL), aggregate);
  return entriesByDll;
};

const sortedEntryRecord = (entries: DllEntries): Record<string, UcrtMetadataEntry> =>
  Object.fromEntries([...entries.entries()].sort(([left], [right]) => left.localeCompare(right)));

const createChunk = (
  dll: string,
  generatedAt: string,
  entries: DllEntries
): UcrtMetadataChunk => ({
  formatVersion: UCRT_METADATA_FORMAT_VERSION,
  generatedAt,
  source: sourceMetadata(),
  dll,
  moduleKey: moduleKey(dll),
  entryCount: entries.size,
  entries: sortedEntryRecord(entries)
});

const manifestChunk = (chunk: UcrtMetadataChunk): UcrtMetadataManifestChunk => ({
  dll: chunk.dll,
  moduleKey: chunk.moduleKey,
  path: chunkFileName(chunk.dll),
  entries: chunk.entryCount
});

const createChunks = (
  entriesByDll: Map<string, DllEntries>,
  generatedAt: string
): UcrtMetadataChunk[] => [...entriesByDll.values()]
  .flatMap(entries => {
    const firstEntry = entries.values().next().value;
    return firstEntry ? [createChunk(firstEntry.module, generatedAt, entries)] : [];
  })
  .sort((left, right) => left.dll.localeCompare(right.dll));

export const buildUcrtMetadataAssets = async (
  headerPackageBytes: Uint8Array,
  importLibraryBytes: Uint8Array,
  generatedAt: string
): Promise<{ manifest: UcrtMetadataManifest; chunks: UcrtMetadataChunk[] }> => {
  const importEntries = readCoffImportLibraryEntries(importLibraryBytes);
  const exportNames = new Set(importEntries.map(entry => entry.exportName));
  const headers = await extractHeaderWorkspace(headerPackageBytes);
  const functions = parseClangFunctions(await runClangAstDump(headers), exportNames);
  const chunks = createChunks(buildEntriesByDll(importEntries, functions), generatedAt);
  const manifest: UcrtMetadataManifest = {
    formatVersion: UCRT_METADATA_FORMAT_VERSION,
    generatedAt,
    source: sourceMetadata(),
    entryCounts: {
      dlls: chunks.length,
      entries: chunks.reduce((total, chunk) => total + chunk.entryCount, 0)
    },
    chunks: chunks.map(manifestChunk)
  };
  return { manifest, chunks };
};

export const chunkOutputName = (chunk: UcrtMetadataChunk): string =>
  chunkFileName(chunk.dll);
