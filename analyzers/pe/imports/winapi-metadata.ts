"use strict";

import type { PeWindowsParseResult } from "../core/parse-result.js";
import type { PeDelayImportEntry } from "./delay.js";
import type { PeDelayImportFunction } from "./delay-thunk-table.js";
import type { PeImportEntry, PeImportFunction, PeImportParseResult } from "./index.js";
import type { PeImportMetadataEntry } from "../../../pe-import-metadata-schema.js";
import {
  isUcrtMetadataChunk,
  isUcrtMetadataManifest,
  type UcrtMetadataChunk,
  type UcrtMetadataManifest
} from "../../../ucrt-metadata-schema.js";
import {
  isWinapiMetadataChunk,
  isWinapiMetadataEntrypointIndex,
  isWinapiMetadataManifest,
  type WinapiMetadataChunk,
  type WinapiMetadataEntrypointIndex,
  type WinapiMetadataEntry,
  type WinapiMetadataManifest
} from "../../../winapi-metadata-schema.js";

const WINAPI_METADATA_BASE_PATH = "winapi-metadata/";
const UCRT_METADATA_BASE_PATH = "ucrt-metadata/";
const API_SET_PREFIX = "api-ms-win-";
const UCRT_API_SET_PREFIX = "api-ms-win-crt-";
const UCRTBASE_MODULE_KEY = "ucrtbase.dll";

type FetchJson = (path: string) => Promise<unknown | null>;

export interface PeWinapiMetadataLookup {
  findEntry: (dll: string, entrypoint: string) => Promise<WinapiMetadataEntry | null>;
}

export interface PeImportMetadataLookup {
  findEntry: (dll: string, entrypoint: string) => Promise<PeImportMetadataEntry | null>;
}

const moduleKey = (moduleName: string): string =>
  moduleName.trim().toLowerCase();

const isApiSetModuleKey = (key: string): boolean =>
  key.startsWith(API_SET_PREFIX) && !key.startsWith(UCRT_API_SET_PREFIX);

const isUcrtModuleKey = (key: string): boolean =>
  key === UCRTBASE_MODULE_KEY || key.startsWith(UCRT_API_SET_PREFIX);

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
  const loaded = fetchMetadataJson(`${WINAPI_METADATA_BASE_PATH}${manifestChunk.path}`).then(json =>
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
    manifestPromise ??= fetchMetadataJson(`${WINAPI_METADATA_BASE_PATH}manifest.json`).then(json =>
      isWinapiMetadataManifest(json) ? json : null);
    return manifestPromise;
  };
  const loadEntrypointIndex = (
    manifest: WinapiMetadataManifest
  ): Promise<WinapiMetadataEntrypointIndex | null> => {
    entrypointIndexPromise ??= fetchMetadataJson(
      `${WINAPI_METADATA_BASE_PATH}${manifest.entrypointIndex.path}`
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

const ucrtManifestChunkForKey = (
  manifest: UcrtMetadataManifest,
  key: string
) => manifest.chunks.find(chunk => chunk.moduleKey === key) ?? null;

const readUcrtChunk = async (
  manifest: UcrtMetadataManifest,
  key: string,
  fetchMetadataJson: FetchJson,
  cache: Map<string, Promise<UcrtMetadataChunk | null>>
): Promise<UcrtMetadataChunk | null> => {
  const manifestChunk = ucrtManifestChunkForKey(manifest, key);
  if (!manifestChunk) return null;
  const cached = cache.get(key);
  if (cached) return cached;
  const loaded = fetchMetadataJson(`${UCRT_METADATA_BASE_PATH}${manifestChunk.path}`).then(json =>
    isUcrtMetadataChunk(json) ? json : null);
  cache.set(key, loaded);
  return loaded;
};

export const createUcrtMetadataLookup = (
  fetchMetadataJson: FetchJson = fetchJson
): PeImportMetadataLookup => {
  let manifestPromise: Promise<UcrtMetadataManifest | null> | null = null;
  const chunkCache = new Map<string, Promise<UcrtMetadataChunk | null>>();
  const loadManifest = (): Promise<UcrtMetadataManifest | null> => {
    manifestPromise ??= fetchMetadataJson(`${UCRT_METADATA_BASE_PATH}manifest.json`).then(json =>
      isUcrtMetadataManifest(json) ? json : null);
    return manifestPromise;
  };
  return {
    findEntry: async (dll: string, entrypoint: string): Promise<PeImportMetadataEntry | null> => {
      const key = moduleKey(dll);
      if (!isUcrtModuleKey(key)) return null;
      const manifest = await loadManifest();
      if (!manifest) return null;
      const chunk = await readUcrtChunk(manifest, key, fetchMetadataJson, chunkCache);
      return chunk?.entries[entrypoint] ?? null;
    }
  };
};

export const createPeImportMetadataLookup = (
  fetchMetadataJson: FetchJson = fetchJson
): PeImportMetadataLookup => {
  const winapi = createWinapiMetadataLookup(fetchMetadataJson);
  const ucrt = createUcrtMetadataLookup(fetchMetadataJson);
  return {
    findEntry: async (dll: string, entrypoint: string): Promise<PeImportMetadataEntry | null> => {
      const key = moduleKey(dll);
      return isUcrtModuleKey(key)
        ? await ucrt.findEntry(dll, entrypoint)
        : await winapi.findEntry(dll, entrypoint);
    }
  };
};

const defaultLookup = createPeImportMetadataLookup();

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
  lookup: PeImportMetadataLookup
): Promise<Map<string, PeImportMetadataEntry>> => {
  const entries = new Map<string, PeImportMetadataEntry>();
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
  entries: ReadonlyMap<string, PeImportMetadataEntry>
): T => {
  const entry = fn.name ? entries.get(importFunctionKey(dll, fn.name)) : null;
  if (!entry) return fn;
  return entry.sourceKind === "winapi"
    ? { ...fn, apiMetadata: entry, winapiMetadata: entry as WinapiMetadataEntry }
    : { ...fn, apiMetadata: entry };
};

const enrichImportEntry = (
  entry: PeImportEntry,
  entries: ReadonlyMap<string, PeImportMetadataEntry>
): PeImportEntry => ({
  ...entry,
  functions: entry.functions.map(fn => enrichFunction(fn, entry.dll, entries))
});

const enrichDelayEntry = (
  entry: PeDelayImportEntry,
  entries: ReadonlyMap<string, PeImportMetadataEntry>
): PeDelayImportEntry => ({
  ...entry,
  functions: entry.functions.map(fn => enrichFunction(fn, entry.name, entries))
});

const enrichImports = (
  imports: PeImportParseResult,
  entries: ReadonlyMap<string, PeImportMetadataEntry>
): PeImportParseResult => ({
  ...imports,
  entries: imports.entries.map(entry => enrichImportEntry(entry, entries))
});

export const enrichPeImportMetadata = async (
  pe: PeWindowsParseResult,
  lookup: PeImportMetadataLookup = defaultLookup
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
