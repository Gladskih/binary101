"use strict";

import { MAX_RVA, type ValidMetadata } from "./metadata.js";
import type { AnalyzePeEntrypointDisassemblyOptions } from "../types.js";
import type { PeImportMetadataEntry } from "../../../../pe-import-metadata-schema.js";

export type ImportTarget = {
  label: string;
  slotRva: number;
  importKind: "eager" | "delay";
  guardIatEntry: boolean;
  apiMetadata?: PeImportMetadataEntry;
};

const formatImportSymbol = (
  imported: { name?: string; ordinal?: number },
  index: number
): string => {
  if (imported.name) return imported.name;
  if (imported.ordinal != null) return `#${imported.ordinal}`;
  return `import[${index}]`;
};

const importApiMetadata = (
  imported: { apiMetadata?: PeImportMetadataEntry; winapiMetadata?: PeImportMetadataEntry }
): PeImportMetadataEntry | undefined =>
  imported.apiMetadata ?? imported.winapiMetadata;

export const buildImportTargetMap = (
  opts: AnalyzePeEntrypointDisassemblyOptions,
  metadata: ValidMetadata
): Map<number, ImportTarget> => {
  const out = new Map<number, ImportTarget>();
  const guardIatRvas = new Set(opts.loadcfg?.tables?.guardIat?.entries.map(entry => entry.rva) ?? []);
  const thunkEntrySize = metadata.bitness === 64 ? 8 : 4;
  const addTarget = (
    startRva: number,
    dll: string,
    imported: {
      name?: string;
      ordinal?: number;
      apiMetadata?: PeImportMetadataEntry;
      winapiMetadata?: PeImportMetadataEntry;
    },
    index: number,
    importKind: "eager" | "delay"
  ): void => {
    const slotRva = startRva + index * thunkEntrySize;
    if (!Number.isSafeInteger(slotRva) || slotRva < 0 || slotRva > MAX_RVA) return;
    const symbol = formatImportSymbol(imported, index);
    const apiMetadata = importApiMetadata(imported);
    out.set(slotRva >>> 0, {
      label: dll ? `${dll}!${symbol}` : symbol,
      slotRva: slotRva >>> 0,
      importKind,
      guardIatEntry: guardIatRvas.has(slotRva >>> 0),
      ...(apiMetadata ? { apiMetadata } : {})
    });
  };
  for (const entry of opts.imports?.entries ?? []) {
    if (!entry.firstThunkRva) continue;
    entry.functions.forEach((imported, index) =>
      addTarget(entry.firstThunkRva, entry.dll, imported, index, "eager")
    );
  }
  for (const entry of opts.delayImports?.entries ?? []) {
    if (!entry.ImportAddressTableRVA) continue;
    entry.functions.forEach((imported, index) =>
      addTarget(entry.ImportAddressTableRVA, entry.name, imported, index, "delay")
    );
  }
  return out;
};
