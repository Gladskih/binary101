"use strict";

import type { PeImportMetadataEntry } from "../../../pe-import-metadata-schema.js";
import type { PeDelayImportEntry } from "../imports/delay.js";
import type { PeImportFunction, PeImportParseResult } from "../imports/index.js";
import { getIatSlotRva } from "./import-references.js";
import type { PeApiStringImportTarget } from "./api-string-reference-model.js";

type ImportFunctionWithMetadata =
  PeImportFunction |
  { apiMetadata?: PeImportMetadataEntry; winapiMetadata?: PeImportMetadataEntry };

const metadataForFunction = (
  fn: ImportFunctionWithMetadata
): PeImportMetadataEntry | null =>
  fn.apiMetadata ?? fn.winapiMetadata ?? null;

const addImportTargets = (
  targets: Map<number, PeApiStringImportTarget>,
  startRva: number,
  entrySize: number,
  functions: ImportFunctionWithMetadata[]
): void => {
  functions.forEach((fn, index) => {
    const metadata = metadataForFunction(fn);
    const slotRva = getIatSlotRva(startRva, index, entrySize);
    if (!metadata || slotRva == null) return;
    targets.set(slotRva, {
      module: metadata.module,
      entrypoint: metadata.entrypoint,
      sourceKind: metadata.sourceKind,
      metadata
    });
  });
};

export const buildPeApiStringImportTargets = (
  is64Bit: boolean,
  imports: PeImportParseResult | undefined,
  delayImports: { entries: PeDelayImportEntry[] } | null | undefined
): Map<number, PeApiStringImportTarget> => {
  const targets = new Map<number, PeApiStringImportTarget>();
  const entrySize = is64Bit
    ? BigUint64Array.BYTES_PER_ELEMENT
    : Uint32Array.BYTES_PER_ELEMENT;
  for (const entry of imports?.entries ?? []) {
    addImportTargets(targets, entry.firstThunkRva, entrySize, entry.functions);
  }
  for (const entry of delayImports?.entries ?? []) {
    addImportTargets(targets, entry.ImportAddressTableRVA, entrySize, entry.functions);
  }
  return targets;
};
