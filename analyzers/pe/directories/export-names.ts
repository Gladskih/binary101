"use strict";

import type { Demangler } from "llvm-msvc-demangle";
import { loadMsvcDemangler } from "#msvc-demangler-loader";

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
  let pending: Promise<Demangler> | undefined;
  let unavailable = false;
  const cache = new Map<string, string | null>();
  return async (names: string[], index: number): Promise<void> => {
    const name = names[index];
    // Presentation resource policy, not an ABI limit. Long names remain available verbatim.
    if (name == null || unavailable || !name.startsWith("?") || name.length > 16 * 1024) return;
    if (cache.has(name)) return storeDisplayName(names, index, cache.get(name) ?? null);
    try {
      pending ??= loadDemangler();
      const result = (await pending).demangleWithText(name);
      if (result.status === "error" || result.status === "limit") {
        throw new Error(result.warnings.join("; ") || result.status);
      }
      const text = result.status === "success" ? result.text : null;
      cache.set(name, text);
      storeDisplayName(names, index, text);
    } catch (error) {
      unavailable = true;
      issues.push("Export name demangling unavailable: " +
        (error instanceof Error ? error.message : String(error)));
    }
  };
};

export const getPeExportDisplayName = (names: readonly string[], index: number): string =>
  displayNames.get(names)?.get(index) ?? names[index] ?? "";
