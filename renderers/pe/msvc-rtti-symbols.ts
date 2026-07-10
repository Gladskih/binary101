"use strict";

import type { CoffDebugInfo } from "../../analyzers/coff/debug-types.js";
import type { PeWindowsParseResult } from "../../analyzers/pe/core/parse-result.js";
import { PE_RVA_EXCLUSIVE_LIMIT } from "../../analyzers/pe/layout/rva-limits.js";

const addName = (
  names: Map<number, string[]>,
  rva: number,
  name: string | null | undefined
): void => {
  if (!Number.isSafeInteger(rva) || rva < 0 || rva >= PE_RVA_EXCLUSIVE_LIMIT || !name) return;
  const existing = names.get(rva);
  if (existing?.includes(name)) return;
  if (existing) existing.push(name);
  else names.set(rva, [name]);
};

const addExportNames = (
  pe: PeWindowsParseResult,
  names: Map<number, string[]>
): void => {
  pe.exports?.entries.forEach(entry => {
    if (!entry.forwarder) addName(names, entry.rva, entry.name);
  });
};

const addPogoNames = (
  pe: PeWindowsParseResult,
  names: Map<number, string[]>
): void => {
  pe.debug?.entries?.forEach(entry => {
    entry.pogo?.entries.forEach(pogoEntry => {
      addName(names, pogoEntry.startRva, pogoEntry.name);
    });
  });
};

const addCoffNames = (
  pe: PeWindowsParseResult,
  info: CoffDebugInfo | null | undefined,
  names: Map<number, string[]>
): void => {
  info?.symbols.forEach(symbol => {
    if (!Number.isInteger(symbol.sectionNumber) || symbol.sectionNumber <= 0) return;
    const section = pe.sections[symbol.sectionNumber - 1];
    if (!section || !Number.isSafeInteger(symbol.value) || symbol.value < 0) return;
    addName(names, (section.virtualAddress >>> 0) + symbol.value, symbol.name);
  });
};

const addGoRuntimeNames = (
  pe: PeWindowsParseResult,
  names: Map<number, string[]>
): void => {
  pe.goRuntime?.functions.forEach(fn => {
    const rva = fn.start - pe.opt.ImageBase;
    if (rva >= 0n && rva < BigInt(PE_RVA_EXCLUSIVE_LIMIT)) addName(names, Number(rva), fn.name);
  });
};

export const collectPeExactSymbolNames = (
  pe: PeWindowsParseResult
): ReadonlyMap<number, readonly string[]> => {
  const names = new Map<number, string[]>();
  addExportNames(pe, names);
  addPogoNames(pe, names);
  addCoffNames(pe, pe.coffDebug, names);
  pe.debug?.entries?.forEach(entry => addCoffNames(pe, entry.coff, names));
  addGoRuntimeNames(pe, names);
  return names;
};
