"use strict";

import type { Demangler } from "llvm-msvc-demangle";
import type { Demangler as ItaniumDemangler } from "llvm-itanium-demangle";
import { loadMsvcDemangler } from "#msvc-demangler-loader";
import { loadItaniumDemangler } from "#itanium-demangler-loader";
import { createPeSymbolNameDecoder, type PeSymbolName } from "../symbol-name.js";

// Decoding follows the original names array through pagination and lazy remounts,
// without adding redundant fields to parsed exports or retaining previous files.
const decodedNames = new WeakMap<readonly string[], Map<number, PeSymbolName>>();

const storeDecodedName = (names: string[], index: number, decoded: PeSymbolName | null): void => {
  if (decoded === null) return;
  const entries = decodedNames.get(names) ?? new Map<number, PeSymbolName>();
  entries.set(index, decoded);
  decodedNames.set(names, entries);
};

export const createPeExportNameDecoder = (
  issues: string[], loadDemangler: () => Promise<Demangler> = loadMsvcDemangler,
  loadItanium: () => Promise<ItaniumDemangler> = loadItaniumDemangler
) => {
  const decode = createPeSymbolNameDecoder(
    message => issues.push("Export name demangling unavailable: " + message), loadDemangler, loadItanium
  );
  return async (names: string[], index: number): Promise<void> => {
    storeDecodedName(names, index, await decode(names[index]));
  };
};

export const getPeExportDisplayName = (names: readonly string[], index: number): string =>
  decodedNames.get(names)?.get(index)?.text ?? names[index] ?? "";

// Positive data kinds from LLVM's MicrosoftDemangleNodes.h; unknown kinds stay eligible.
// https://github.com/llvm/llvm-project/blob/main/llvm/include/llvm/Demangle/MicrosoftDemangleNodes.h
const dataSymbolKinds = new Set<PeSymbolName["symbolKind"]>(["VariableSymbol", "SpecialTableSymbol",
  "LocalStaticGuardVariable", "EncodedStringLiteral", "ItaniumData", "DlangData"]);

export const isPeExportData = (names: readonly string[]): boolean =>
  names.some((_name, index) => dataSymbolKinds.has(decodedNames.get(names)?.get(index)?.symbolKind));
