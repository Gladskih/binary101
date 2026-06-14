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
  sections: PeSection[]
) => Promise<PeLoadConfig | null>;

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

export const createLoadConfigEnricher = (
  parseLoadConfigDirectory: LoadConfigParser,
  parseDynamicRelocationsFromLoadConfig: DynamicRelocationParser,
  readSafeSehHandlerTable: SafeSehTableReader | null
): LoadConfigEnricher => async (
  reader,
  dataDirs,
  rvaToOff,
  imageBase,
  sizeOfImage,
  sections
) => {
  const loadcfg = await parseLoadConfigDirectory(reader, dataDirs, rvaToOff);
  if (!loadcfg) return null;
  const diagnostics = collectLoadConfigDiagnostics(
    reader.size,
    rvaToOff,
    imageBase,
    sizeOfImage,
    loadcfg
  );
  mergeLoadConfigWarnings(loadcfg, diagnostics.warnings);
  mergeLoadConfigNotes(loadcfg, diagnostics.notes);
  const tables: PeLoadConfigTables = {};
  const guardFlags = loadcfg.GuardFlags;
  if (loadcfg.GuardCFFunctionCount > 0) {
    assignTable(tables, "guardFid", await readOptionalTable(loadcfg, () =>
      readGuardCFFunctionTable(
        reader,
        rvaToOff,
        imageBase,
        loadcfg.GuardCFFunctionTable,
        loadcfg.GuardCFFunctionCount,
        guardFlags
      ), "GuardCFFunctionTable"));
  }
  if (loadcfg.GuardEHContinuationCount > 0) {
    assignTable(tables, "guardEhContinuation", await readOptionalTable(loadcfg, () =>
      readGuardEhContinuationTable(
        reader,
        rvaToOff,
        imageBase,
        loadcfg.GuardEHContinuationTable,
        loadcfg.GuardEHContinuationCount,
        guardFlags
      ), "GuardEHContinuationTable"));
  }
  if (loadcfg.GuardLongJumpTargetCount > 0) {
    assignTable(tables, "guardLongJumpTarget", await readOptionalTable(loadcfg, () =>
      readGuardLongJumpTargetTable(
        reader,
        rvaToOff,
        imageBase,
        loadcfg.GuardLongJumpTargetTable,
        loadcfg.GuardLongJumpTargetCount,
        guardFlags
      ), "GuardLongJumpTargetTable"));
  }
  if (loadcfg.GuardAddressTakenIatEntryCount > 0) {
    assignTable(tables, "guardIat", await readOptionalTable(loadcfg, () =>
      readGuardAddressTakenIatEntryTable(
        reader,
        rvaToOff,
        imageBase,
        loadcfg.GuardAddressTakenIatEntryTable,
        loadcfg.GuardAddressTakenIatEntryCount,
        guardFlags
      ), "GuardAddressTakenIatEntryTable"));
  }
  if (readSafeSehHandlerTable && loadcfg.SEHandlerCount > 0) {
    assignTable(tables, "safeSehHandler", await readOptionalTable(loadcfg, () =>
      readSafeSehHandlerTable(
        reader,
        rvaToOff,
        imageBase,
        loadcfg.SEHandlerTable,
        loadcfg.SEHandlerCount
      ), "SEHandlerTable"));
  }
  if (Object.values(tables).some(table => table != null)) loadcfg.tables = tables;
  try {
    loadcfg.dynamicRelocations = await parseDynamicRelocationsFromLoadConfig(
      reader,
      sections,
      rvaToOff,
      imageBase,
      loadcfg
    );
  } catch (error) {
    mergeLoadConfigWarnings(loadcfg, [`LOAD_CONFIG: failed to read dynamic relocations (${String(error)}).`]);
    loadcfg.dynamicRelocations = null;
  }
  return loadcfg;
};
