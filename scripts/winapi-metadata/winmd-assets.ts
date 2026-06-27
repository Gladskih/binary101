"use strict";

import { isPeWindowsParseResult, parsePe } from "../../analyzers/pe/index.js";
import type {
  PeClrCustomAttributeInfo,
  PeClrImplementationMapInfo,
  PeClrMetadataTables,
  PeClrMethodDefinitionInfo
} from "../../analyzers/pe/clr/types.js";
import type {
  ManifestXmlDocument,
  ManifestXmlDocumentParser,
  ManifestXmlNodeList
} from "../../analyzers/pe/resources/preview/manifest-xml.js";
import {
  WINAPI_METADATA_FORMAT_VERSION,
  type WinapiMetadataChunk,
  type WinapiMetadataEntrypointIndex,
  type WinapiMetadataEntry,
  type WinapiMetadataManifest,
  type WinapiMetadataManifestChunk,
  type WinapiMetadataSource
} from "../../winapi-metadata-schema.js";
import { WINAPI_METADATA_PACKAGE } from "./config.js";
import {
  buildWinapiParameters,
  formatWinapiSignature,
  resolveSignatureType
} from "./signature-format.js";
import {
  decodeCallingConvention,
  decodeCharacterSet,
  isVariadicConvention,
  mappingSupportsLastError
} from "./pinvoke-flags.js";

const METHOD_DEF_TABLE_ID = 0x06;
const API_TYPE_SUFFIX = ".Apis";
const ANSI_ATTRIBUTE = "Windows.Win32.Foundation.Metadata.AnsiAttribute";
const UNICODE_ATTRIBUTE = "Windows.Win32.Foundation.Metadata.UnicodeAttribute";
const SUPPORTED_OS_ATTRIBUTE = "Windows.Win32.Foundation.Metadata.SupportedOSPlatformAttribute";
const SUPPORTED_ARCHITECTURE_ATTRIBUTE = "Windows.Win32.Foundation.Metadata.SupportedArchitectureAttribute";
export const WINAPI_METADATA_ENTRYPOINT_INDEX_PATH = "entrypoint-index.json";

type DllEntries = Map<string, WinapiMetadataEntry>;

const emptyXmlNodeList: ManifestXmlNodeList = Object.assign([], { item: () => null });

const parseEmptyXmlDocument: ManifestXmlDocumentParser = (): ManifestXmlDocument => ({
  documentElement: null,
  getElementsByTagName: () => emptyXmlNodeList
});

const sourceMetadata = (): WinapiMetadataSource => ({
  packageName: WINAPI_METADATA_PACKAGE.name,
  packageVersion: WINAPI_METADATA_PACKAGE.version,
  fileName: WINAPI_METADATA_PACKAGE.winmdPath
});

const isLoadableImportScope = (moduleName: string): boolean =>
  moduleName.includes(".");

export const moduleKey = (moduleName: string): string =>
  moduleName.toLowerCase();

const isApiSetModuleKey = (key: string): boolean =>
  key.startsWith("api-ms-win-");

const chunkFileName = (moduleName: string): string =>
  `${moduleKey(moduleName).replaceAll(/[^a-z0-9._-]/g, "_")}.json`;

const tokenHex = (method: PeClrMethodDefinitionInfo): string =>
  `0x${(((METHOD_DEF_TABLE_ID << 24) | method.row) >>> 0).toString(16).padStart(8, "0")}`;

const namespaceFromOwner = (ownerType: string | null): string | null => {
  if (!ownerType) return null;
  return ownerType.endsWith(API_TYPE_SUFFIX)
    ? ownerType.slice(0, -API_TYPE_SUFFIX.length)
    : ownerType;
};

const attributesForMethod = (
  method: PeClrMethodDefinitionInfo,
  attributes: PeClrCustomAttributeInfo[]
): PeClrCustomAttributeInfo[] =>
  attributes.filter(attribute =>
    attribute.parent.tableId === METHOD_DEF_TABLE_ID && attribute.parent.row === method.row);

const firstStringArgument = (attribute: PeClrCustomAttributeInfo): string | null => {
  const value = attribute.fixedArguments[0]?.value;
  return typeof value === "string" ? value : null;
};

const platformConstraints = (attributes: PeClrCustomAttributeInfo[]): string[] =>
  attributes
    .filter(attribute => attribute.attributeType === SUPPORTED_OS_ATTRIBUTE)
    .map(firstStringArgument)
    .filter((value): value is string => value != null);

const architectureLabels = (value: number): string[] => {
  const labels: string[] = [];
  if ((value & 0x1) !== 0) labels.push("x86");
  if ((value & 0x2) !== 0) labels.push("x64");
  if ((value & 0x4) !== 0) labels.push("arm64");
  const unknownBits = value & ~0x7;
  if (unknownBits !== 0) labels.push(`unknown:${unknownBits}`);
  return labels.length ? labels : [`raw:${value}`];
};

const architectureConstraints = (attributes: PeClrCustomAttributeInfo[]): string[] =>
  attributes
    .filter(attribute => attribute.attributeType === SUPPORTED_ARCHITECTURE_ATTRIBUTE)
    .flatMap(attribute =>
      typeof attribute.fixedArguments[0]?.value === "number"
        ? architectureLabels(attribute.fixedArguments[0].value)
        : []);

const characterSet = (
  mappingFlags: number,
  attributes: PeClrCustomAttributeInfo[]
): string | null => {
  if (attributes.some(attribute => attribute.attributeType === ANSI_ATTRIBUTE)) return "ansi";
  if (attributes.some(attribute => attribute.attributeType === UNICODE_ATTRIBUTE)) return "unicode";
  return decodeCharacterSet(mappingFlags);
};

const createEntry = (
  implMap: PeClrImplementationMapInfo,
  method: PeClrMethodDefinitionInfo,
  attributes: PeClrCustomAttributeInfo[],
  tables: PeClrMetadataTables
): WinapiMetadataEntry | null => {
  const api = method.name ?? implMap.memberName ?? implMap.importName;
  const module = implMap.importScopeName;
  const entrypoint = implMap.importName;
  if (!api || !module || !entrypoint || !isLoadableImportScope(module)) return null;
  const parameters = buildWinapiParameters(method, tables);
  return {
    sourceKind: "winapi",
    id: `MethodDef:${tokenHex(method)};ImplMap:${implMap.row}`,
    module,
    entrypoint,
    namespace: namespaceFromOwner(method.ownerType),
    api,
    signature: formatWinapiSignature(method, api, tables),
    returnType: resolveSignatureType(method.signature?.returnType, tables),
    rawReturnType: method.signature?.returnType ?? null,
    parameters,
    callingConvention: decodeCallingConvention(implMap.mappingFlags),
    variadic: isVariadicConvention(implMap.mappingFlags),
    setLastError: mappingSupportsLastError(implMap.mappingFlags),
    characterSet: characterSet(implMap.mappingFlags, attributes),
    architecture: architectureConstraints(attributes),
    platform: platformConstraints(attributes)
  };
};

const addEntry = (
  entriesByDll: Map<string, DllEntries>,
  entry: WinapiMetadataEntry
): void => {
  const key = moduleKey(entry.module);
  const entries = entriesByDll.get(key) ?? new Map<string, WinapiMetadataEntry>();
  entries.set(entry.entrypoint, entry);
  entriesByDll.set(key, entries);
};

const buildEntriesByDll = (tables: PeClrMetadataTables): Map<string, DllEntries> => {
  const methodsByRow = new Map(tables.methodDefs.map(method => [method.row, method]));
  const entriesByDll = new Map<string, DllEntries>();
  tables.implMaps.forEach(implMap => {
    if (implMap.member.tableId !== METHOD_DEF_TABLE_ID) return;
    const method = methodsByRow.get(implMap.member.row);
    if (!method) return;
    const entry = createEntry(implMap, method, attributesForMethod(method, tables.customAttributes), tables);
    if (entry) addEntry(entriesByDll, entry);
  });
  return entriesByDll;
};

const sortedEntryRecord = (entries: DllEntries): Record<string, WinapiMetadataEntry> =>
  Object.fromEntries([...entries.entries()].sort(([left], [right]) => left.localeCompare(right)));

const createChunk = (
  dll: string,
  generatedAt: string,
  entries: DllEntries
): WinapiMetadataChunk => ({
  formatVersion: WINAPI_METADATA_FORMAT_VERSION,
  generatedAt,
  source: sourceMetadata(),
  dll,
  moduleKey: moduleKey(dll),
  entryCount: entries.size,
  entries: sortedEntryRecord(entries)
});

const manifestChunk = (chunk: WinapiMetadataChunk): WinapiMetadataManifestChunk => ({
  dll: chunk.dll,
  moduleKey: chunk.moduleKey,
  path: chunkFileName(chunk.dll),
  entries: chunk.entryCount
});

const buildEntrypointIndexEntries = (chunks: WinapiMetadataChunk[]): Record<string, string[]> => {
  const entries = new Map<string, Set<string>>();
  chunks.filter(chunk => !isApiSetModuleKey(chunk.moduleKey)).forEach(chunk => {
    Object.keys(chunk.entries).forEach(entrypoint => {
      const moduleKeys = entries.get(entrypoint) ?? new Set<string>();
      moduleKeys.add(chunk.moduleKey);
      entries.set(entrypoint, moduleKeys);
    });
  });
  return Object.fromEntries([...entries.entries()]
    .sort(([left], [right]) => left.localeCompare(right))
    .map(([entrypoint, moduleKeys]) => [entrypoint, [...moduleKeys].sort()]));
};

const createEntrypointIndex = (
  chunks: WinapiMetadataChunk[],
  generatedAt: string
): WinapiMetadataEntrypointIndex => {
  const entries = buildEntrypointIndexEntries(chunks);
  return {
    formatVersion: WINAPI_METADATA_FORMAT_VERSION,
    generatedAt,
    source: sourceMetadata(),
    entryCount: Object.keys(entries).length,
    referenceCount: Object.values(entries).reduce((total, moduleKeys) => total + moduleKeys.length, 0),
    entries
  };
};

export const readWinmdMetadataTables = async (
  winmdBytes: Uint8Array
): Promise<PeClrMetadataTables> => {
  const bytes = new Uint8Array(winmdBytes.byteLength);
  bytes.set(winmdBytes);
  const pe = await parsePe(new File([bytes.buffer], WINAPI_METADATA_PACKAGE.winmdPath), parseEmptyXmlDocument);
  if (!pe || !isPeWindowsParseResult(pe) || !pe.clr?.meta?.tables) {
    throw new Error("Windows.Win32.winmd did not contain readable CLR metadata tables.");
  }
  return pe.clr.meta.tables;
};

export const buildWinapiMetadataAssets = async (
  winmdBytes: Uint8Array,
  generatedAt: string
): Promise<{
  manifest: WinapiMetadataManifest;
  chunks: WinapiMetadataChunk[];
  entrypointIndex: WinapiMetadataEntrypointIndex;
}> => {
  const chunks = [...buildEntriesByDll(await readWinmdMetadataTables(winmdBytes)).entries()]
    .flatMap(([_key, entries]) => {
      const firstEntry = entries.values().next().value;
      return firstEntry ? [createChunk(firstEntry.module, generatedAt, entries)] : [];
    })
    .sort((left, right) => left.dll.localeCompare(right.dll));
  const entrypointIndex = createEntrypointIndex(chunks, generatedAt);
  const manifest: WinapiMetadataManifest = {
    formatVersion: WINAPI_METADATA_FORMAT_VERSION,
    generatedAt,
    source: sourceMetadata(),
    entryCounts: {
      dlls: chunks.length,
      entries: chunks.reduce((total, chunk) => total + chunk.entryCount, 0)
    },
    entrypointIndex: {
      path: WINAPI_METADATA_ENTRYPOINT_INDEX_PATH,
      entries: entrypointIndex.entryCount,
      references: entrypointIndex.referenceCount
    },
    chunks: chunks.map(manifestChunk)
  };
  return { manifest, chunks, entrypointIndex };
};

export const chunkOutputName = (chunk: WinapiMetadataChunk): string =>
  chunkFileName(chunk.dll);
