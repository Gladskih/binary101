"use strict";

import type { PeWindowsParseResult } from "../core/parse-result.js";
import type { PeDelayImportEntry } from "./delay.js";
import type { PeDelayImportFunction } from "./delay-thunk-table.js";
import type { PeImportEntry, PeImportFunction, PeImportParseResult } from "./index.js";
import {
  isWinapiMetadataChunk,
  isWinapiMetadataEntrypointIndex,
  isWinapiMetadataManifest,
  type WinapiMetadataChunk,
  type WinapiMetadataEntrypointIndex,
  type WinapiMetadataEntry,
  type WinapiMetadataManifest
} from "../../../winapi-metadata-schema.js";

const METADATA_BASE_PATH = "winapi-metadata/";
const API_SET_PREFIX = "api-ms-win-";

type FetchJson = (path: string) => Promise<unknown | null>;

export interface PeWinapiMetadataLookup {
  findEntry: (dll: string, entrypoint: string) => Promise<WinapiMetadataEntry | null>;
}

const moduleKey = (moduleName: string): string =>
  moduleName.trim().toLowerCase();

const isApiSetModuleKey = (key: string): boolean =>
  key.startsWith(API_SET_PREFIX);

const parseJsonResponse = async (response: Response): Promise<unknown> =>
  JSON.parse(await response.text()) as unknown;

const fetchJson: FetchJson = async (path: string): Promise<unknown | null> => {
  if (typeof fetch !== "function") return null;
  try {
    const response = await fetch(path);
    return response.ok ? await parseJsonResponse(response) : null;
  } catch {
    return null;
  }
};

const manifestChunkForKey = (
  manifest: WinapiMetadataManifest,
  key: string
) => manifest.chunks.find(chunk => chunk.moduleKey === key) ?? null;

const readChunk = async (
  manifest: WinapiMetadataManifest,
  key: string,
  fetchMetadataJson: FetchJson,
  cache: Map<string, Promise<WinapiMetadataChunk | null>>
): Promise<WinapiMetadataChunk | null> => {
  const manifestChunk = manifestChunkForKey(manifest, key);
  if (!manifestChunk) return null;
  const cached = cache.get(key);
  if (cached) return cached;
  const loaded = fetchMetadataJson(`${METADATA_BASE_PATH}${manifestChunk.path}`).then(json =>
    isWinapiMetadataChunk(json) ? json : null);
  cache.set(key, loaded);
  return loaded;
};

export const createWinapiMetadataLookup = (
  fetchMetadataJson: FetchJson = fetchJson
): PeWinapiMetadataLookup => {
  let manifestPromise: Promise<WinapiMetadataManifest | null> | null = null;
  let entrypointIndexPromise: Promise<WinapiMetadataEntrypointIndex | null> | null = null;
  const chunkCache = new Map<string, Promise<WinapiMetadataChunk | null>>();
  const loadManifest = (): Promise<WinapiMetadataManifest | null> => {
    manifestPromise ??= fetchMetadataJson(`${METADATA_BASE_PATH}manifest.json`).then(json =>
      isWinapiMetadataManifest(json) ? json : null);
    return manifestPromise;
  };
  const loadEntrypointIndex = (
    manifest: WinapiMetadataManifest
  ): Promise<WinapiMetadataEntrypointIndex | null> => {
    entrypointIndexPromise ??= fetchMetadataJson(
      `${METADATA_BASE_PATH}${manifest.entrypointIndex.path}`
    ).then(json => isWinapiMetadataEntrypointIndex(json) ? json : null);
    return entrypointIndexPromise;
  };
  const findApiSetFallback = async (
    manifest: WinapiMetadataManifest,
    entrypoint: string
  ): Promise<WinapiMetadataEntry | null> => {
    const entrypointIndex = await loadEntrypointIndex(manifest);
    const candidateKeys = entrypointIndex?.entries[entrypoint] ?? [];
    for (const candidateKey of candidateKeys) {
      const chunk = await readChunk(manifest, candidateKey, fetchMetadataJson, chunkCache);
      const entry = chunk?.entries[entrypoint];
      if (entry) return entry;
    }
    return null;
  };
  return {
    findEntry: async (dll: string, entrypoint: string): Promise<WinapiMetadataEntry | null> => {
      const manifest = await loadManifest();
      if (!manifest) return null;
      const key = moduleKey(dll);
      const chunk = await readChunk(manifest, key, fetchMetadataJson, chunkCache);
      return chunk?.entries[entrypoint] ??
        (isApiSetModuleKey(key) ? await findApiSetFallback(manifest, entrypoint) : null);
    }
  };
};

const defaultLookup = createWinapiMetadataLookup();

const importFunctionKey = (dll: string, name: string): string =>
  `${moduleKey(dll)}\u0000${name}`;

const namedImportFunctions = (
  pe: PeWindowsParseResult
): Array<{ dll: string; name: string }> => [
  ...pe.imports.entries.flatMap(entry =>
    entry.functions.flatMap(fn => fn.name ? [{ dll: entry.dll, name: fn.name }] : [])),
  ...(pe.delayImports?.entries.flatMap(entry =>
    entry.functions.flatMap(fn => fn.name ? [{ dll: entry.name, name: fn.name }] : [])) ?? [])
];

const loadImportMetadata = async (
  pe: PeWindowsParseResult,
  lookup: PeWinapiMetadataLookup
): Promise<Map<string, WinapiMetadataEntry>> => {
  const entries = new Map<string, WinapiMetadataEntry>();
  const imports = [...new Map(namedImportFunctions(pe).map(item => [
    importFunctionKey(item.dll, item.name),
    item
  ])).values()];
  await Promise.all(imports.map(async imported => {
    const entry = await lookup.findEntry(imported.dll, imported.name);
    if (entry) entries.set(importFunctionKey(imported.dll, imported.name), entry);
  }));
  return entries;
};

const enrichFunction = <T extends PeDelayImportFunction | PeImportFunction>(
  fn: T,
  dll: string,
  entries: ReadonlyMap<string, WinapiMetadataEntry>
): T => {
  const entry = fn.name ? entries.get(importFunctionKey(dll, fn.name)) : null;
  return entry ? { ...fn, winapiMetadata: entry } : fn;
};

const enrichImportEntry = (
  entry: PeImportEntry,
  entries: ReadonlyMap<string, WinapiMetadataEntry>
): PeImportEntry => ({
  ...entry,
  functions: entry.functions.map(fn => enrichFunction(fn, entry.dll, entries))
});

const enrichDelayEntry = (
  entry: PeDelayImportEntry,
  entries: ReadonlyMap<string, WinapiMetadataEntry>
): PeDelayImportEntry => ({
  ...entry,
  functions: entry.functions.map(fn => enrichFunction(fn, entry.name, entries))
});

const enrichImports = (
  imports: PeImportParseResult,
  entries: ReadonlyMap<string, WinapiMetadataEntry>
): PeImportParseResult => ({
  ...imports,
  entries: imports.entries.map(entry => enrichImportEntry(entry, entries))
});

export const enrichPeImportMetadata = async (
  pe: PeWindowsParseResult,
  lookup: PeWinapiMetadataLookup = defaultLookup
): Promise<PeWindowsParseResult> => {
  const entries = await loadImportMetadata(pe, lookup);
  if (!entries.size) return pe;
  return {
    ...pe,
    imports: enrichImports(pe.imports, entries),
    delayImports: pe.delayImports
      ? { ...pe.delayImports, entries: pe.delayImports.entries.map(entry => enrichDelayEntry(entry, entries)) }
      : pe.delayImports
  };
};
