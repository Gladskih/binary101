"use strict";

import type { Demangler } from "llvm-msvc-demangle";
import { loadMsvcDemangler } from "#msvc-demangler-loader";
import { createMsvcSymbolNameDecoder } from "../msvc-demangle/symbol-name.js";

// Presentation follows the original names array through pagination and lazy remounts,
// without adding redundant fields to parsed exports or retaining previous files.
const displayNames = new WeakMap<readonly string[], Map<number, string>>();

const storeDisplayName = (names: string[], index: number, text: string | null): void => {
  if (text === null) return;
  const displays = displayNames.get(names) ?? new Map<number, string>();
  displays.set(index, text);
  displayNames.set(names, displays);
};

export const createPeExportNameDecoder = (
  issues: string[], loadDemangler: () => Promise<Demangler> = loadMsvcDemangler
) => {
  const decode = createMsvcSymbolNameDecoder(
    message => issues.push("Export name demangling unavailable: " + message), loadDemangler
  );
  return async (names: string[], index: number): Promise<void> => {
    storeDisplayName(names, index, await decode(names[index]));
  };
};

export const getPeExportDisplayName = (names: readonly string[], index: number): string =>
  displayNames.get(names)?.get(index) ?? names[index] ?? "";
