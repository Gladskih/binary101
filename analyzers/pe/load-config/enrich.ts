"use strict";

import type { FileRangeReader } from "../../file-range-reader.js";
import type { PeDynamicRelocations } from "../dynamic-relocations/index.js";
import type { PeDataDirectory, PeSection, RvaToOffset } from "../types.js";
import type { PeLoadConfig, PeLoadConfigTable, PeLoadConfigTables } from "./index.js";
import {
  readGuardAddressTakenIatEntryTable,
  readGuardCFFunctionTable,
  readGuardEhContinuationTable,
  readGuardLongJumpTargetTable
} from "./tables.js";
import { parseLoadConfigReferences } from "./references.js";
import type { PePointerBytes } from "./reference-reader.js";
import { collectLoadConfigDiagnostics } from "./warnings.js";

type LoadConfigParser = (
  reader: FileRangeReader,
  dataDirs: PeDataDirectory[],
  rvaToOff: RvaToOffset
) => Promise<PeLoadConfig | null>;

type DynamicRelocationParser = (
  reader: FileRangeReader,
  sections: PeSection[],
  rvaToOff: RvaToOffset,
  imageBase: bigint,
  loadConfig: PeLoadConfig
) => Promise<PeDynamicRelocations | null>;

type SafeSehTableReader = (
  reader: FileRangeReader,
  rvaToOff: RvaToOffset,
  imageBase: bigint,
  seHandlerTableVa: bigint,
  seHandlerCount: number
) => Promise<PeLoadConfigTable>;

type LoadConfigEnricher = (
  reader: FileRangeReader,
  dataDirs: PeDataDirectory[],
  rvaToOff: RvaToOffset,
  imageBase: bigint,
  sizeOfImage: number,
  sizeOfHeaders: number,
  sections: PeSection[]
) => Promise<PeLoadConfig | null>;

type LoadConfigEnrichmentStrategy = Readonly<{
  parseDirectory: LoadConfigParser;
  parseDynamicRelocations: DynamicRelocationParser;
  readSafeSehTable: SafeSehTableReader | null;
  pointerBytes: PePointerBytes;
}>;

const appendUniqueMessages = (existing: string[] | undefined, messages: string[]): string[] | undefined =>
  messages.length ? [...new Set([...(existing ?? []), ...messages])] : existing;

const mergeLoadConfigWarnings = (loadcfg: PeLoadConfig, messages: string[]): void => {
  const merged = appendUniqueMessages(loadcfg.warnings, messages);
  if (merged?.length) loadcfg.warnings = merged;
};

const mergeLoadConfigNotes = (loadcfg: PeLoadConfig, messages: string[]): void => {
  const merged = appendUniqueMessages(loadcfg.notes, messages);
  if (merged?.length) loadcfg.notes = merged;
};

const readOptionalTable = async (
  loadcfg: PeLoadConfig,
  readTable: () => Promise<PeLoadConfigTable>,
  warningName: string
): Promise<PeLoadConfigTable | undefined> => {
  try {
    return await readTable();
  } catch (error) {
    mergeLoadConfigWarnings(loadcfg, [`LOAD_CONFIG: failed to read ${warningName} (${String(error)}).`]);
    return undefined;
  }
};

const assignTable = (
  tables: PeLoadConfigTables,
  name: keyof PeLoadConfigTables,
  table: PeLoadConfigTable | undefined
): void => {
  if (table) tables[name] = table;
};

const readAndAttachReferences = async (
  loadConfig: PeLoadConfig,
  reader: FileRangeReader,
  sections: PeSection[],
  sizeOfHeaders: number,
  rvaToOff: RvaToOffset,
  imageBase: bigint,
  pointerBytes: PePointerBytes
): Promise<void> => {
  try {
    const references = await parseLoadConfigReferences(
      reader, sections, sizeOfHeaders, rvaToOff, imageBase, pointerBytes, loadConfig
    );
    loadConfig.references = references;
    mergeLoadConfigWarnings(loadConfig, references.warnings ?? []);
    mergeLoadConfigNotes(loadConfig, references.notes ?? []);
  } catch (error) {
    mergeLoadConfigWarnings(loadConfig, [`LOAD_CONFIG: failed to read referenced structures (${String(error)}).`]);
  }
};

const readAndAttachTables = async (
  loadConfig: PeLoadConfig,
  reader: FileRangeReader,
  rvaToOff: RvaToOffset,
  imageBase: bigint,
  readSafeSehTable: SafeSehTableReader | null
): Promise<void> => {
  const guardFlags = loadConfig.GuardFlags;
  const candidates: readonly (readonly [
    count: number,
    key: keyof PeLoadConfigTables,
    label: string,
    read: () => Promise<PeLoadConfigTable>
  ])[] = [
    [loadConfig.GuardCFFunctionCount, "guardFid", "GuardCFFunctionTable", () =>
      readGuardCFFunctionTable(
        reader, rvaToOff, imageBase, loadConfig.GuardCFFunctionTable,
        loadConfig.GuardCFFunctionCount, guardFlags
      )],
    [loadConfig.GuardEHContinuationCount, "guardEhContinuation", "GuardEHContinuationTable", () =>
      readGuardEhContinuationTable(
        reader, rvaToOff, imageBase, loadConfig.GuardEHContinuationTable,
        loadConfig.GuardEHContinuationCount, guardFlags
      )],
    [loadConfig.GuardLongJumpTargetCount, "guardLongJumpTarget", "GuardLongJumpTargetTable", () =>
      readGuardLongJumpTargetTable(
        reader, rvaToOff, imageBase, loadConfig.GuardLongJumpTargetTable,
        loadConfig.GuardLongJumpTargetCount, guardFlags
      )],
    [loadConfig.GuardAddressTakenIatEntryCount, "guardIat", "GuardAddressTakenIatEntryTable", () =>
      readGuardAddressTakenIatEntryTable(
        reader, rvaToOff, imageBase, loadConfig.GuardAddressTakenIatEntryTable,
        loadConfig.GuardAddressTakenIatEntryCount, guardFlags
      )],
    ...(readSafeSehTable ? [[
      loadConfig.SEHandlerCount, "safeSehHandler" as const, "SEHandlerTable", () =>
        readSafeSehTable(
          reader, rvaToOff, imageBase, loadConfig.SEHandlerTable, loadConfig.SEHandlerCount
        )
    ] as const] : [])
  ];
  const tables: PeLoadConfigTables = {};
  for (const [count, key, label, read] of candidates) {
    if (count > 0) assignTable(tables, key, await readOptionalTable(loadConfig, read, label));
  }
  if (Object.values(tables).some(table => table != null)) loadConfig.tables = tables;
};

const readAndAttachDynamicRelocations = async (
  loadConfig: PeLoadConfig,
  reader: FileRangeReader,
  sections: PeSection[],
  rvaToOff: RvaToOffset,
  imageBase: bigint,
  parseDynamicRelocations: DynamicRelocationParser
): Promise<void> => {
  try {
    loadConfig.dynamicRelocations = await parseDynamicRelocations(
      reader, sections, rvaToOff, imageBase, loadConfig
    );
  } catch (error) {
    mergeLoadConfigWarnings(loadConfig,
      [`LOAD_CONFIG: failed to read dynamic relocations (${String(error)}).`]);
    loadConfig.dynamicRelocations = null;
  }
};

const enrichLoadConfig = async (
  strategy: LoadConfigEnrichmentStrategy,
  reader: FileRangeReader,
  dataDirs: PeDataDirectory[],
  rvaToOff: RvaToOffset,
  imageBase: bigint,
  sizeOfImage: number,
  sizeOfHeaders: number,
  sections: PeSection[]
): Promise<PeLoadConfig | null> => {
  const loadConfig = await strategy.parseDirectory(reader, dataDirs, rvaToOff);
  if (!loadConfig) return null;
  const diagnostics = collectLoadConfigDiagnostics(
    reader.size, rvaToOff, imageBase, sizeOfImage, loadConfig
  );
  mergeLoadConfigWarnings(loadConfig, diagnostics.warnings);
  mergeLoadConfigNotes(loadConfig, diagnostics.notes);
  await readAndAttachTables(
    loadConfig, reader, rvaToOff, imageBase, strategy.readSafeSehTable
  );
  await readAndAttachDynamicRelocations(
    loadConfig, reader, sections, rvaToOff, imageBase, strategy.parseDynamicRelocations
  );
  await readAndAttachReferences(
    loadConfig, reader, sections, sizeOfHeaders, rvaToOff, imageBase, strategy.pointerBytes
  );
  return loadConfig;
};

export const createLoadConfigEnricher = (
  parseLoadConfigDirectory: LoadConfigParser,
  parseDynamicRelocationsFromLoadConfig: DynamicRelocationParser,
  readSafeSehHandlerTable: SafeSehTableReader | null,
  pointerBytes: PePointerBytes
): LoadConfigEnricher => {
  const strategy: LoadConfigEnrichmentStrategy = {
    parseDirectory: parseLoadConfigDirectory,
    parseDynamicRelocations: parseDynamicRelocationsFromLoadConfig,
    readSafeSehTable: readSafeSehHandlerTable,
    pointerBytes
  };
  return (reader, directories, rvaToOff, imageBase, sizeOfImage, sizeOfHeaders, sections) =>
    enrichLoadConfig(
      strategy, reader, directories, rvaToOff, imageBase, sizeOfImage, sizeOfHeaders, sections
    );
};
