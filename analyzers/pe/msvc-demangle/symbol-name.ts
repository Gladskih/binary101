"use strict";

import type { Demangler } from "llvm-msvc-demangle";
import { loadMsvcDemangler } from "#msvc-demangler-loader";

export const createMsvcSymbolNameDecoder = (
  reportFailure: (message: string) => void,
  loadDemangler: () => Promise<Demangler> = loadMsvcDemangler
) => {
  let pending: Promise<Demangler> | undefined;
  let unavailable = false;
  const cache = new Map<string, string | null>();
  return async (name: string | undefined): Promise<string | null> => {
    // Presentation resource policy, not an ABI limit. Raw names are retained.
    if (name == null || unavailable || !name.startsWith("?") || name.length > 16 * 1024) return null;
    if (cache.has(name)) return cache.get(name) ?? null;
    try {
      pending ??= loadDemangler();
      const result = (await pending).demangleWithText(name);
      if (result.status === "error" || result.status === "limit") {
        throw new Error(result.warnings.join("; ") || result.status);
      }
      const text = result.status === "success" ? result.text : null;
      cache.set(name, text);
      return text;
    } catch (error) {
      unavailable = true;
      reportFailure(error instanceof Error ? error.message : String(error));
      return null;
    }
  };
};
