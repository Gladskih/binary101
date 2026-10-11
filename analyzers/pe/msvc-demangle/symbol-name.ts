"use strict";

import type { AstNode, Demangler } from "llvm-msvc-demangle";
import { loadMsvcDemangler } from "#msvc-demangler-loader";

export type MsvcSymbolName = { text: string; symbolKind: AstNode["kind"] | undefined };

export const createMsvcSymbolNameDecoder = (
  reportFailure: (message: string) => void,
  loadDemangler: () => Promise<Demangler> = loadMsvcDemangler
) => {
  let pending: Promise<Demangler> | undefined;
  let unavailable = false;
  const cache = new Map<string, MsvcSymbolName | null>();
  return async (name: string | undefined): Promise<MsvcSymbolName | null> => {
    // Presentation resource policy, not an ABI limit. Raw names are retained.
    if (name == null || unavailable || !name.startsWith("?") || name.length > 16 * 1024) return null;
    if (cache.has(name)) return cache.get(name) ?? null;
    try {
      pending ??= loadDemangler();
      const result = (await pending).demangleWithText(name);
      if (result.status === "error" || result.status === "limit") {
        throw new Error(result.warnings.join("; ") || result.status);
      }
      const decoded = result.status === "success"
        ? { text: result.text, symbolKind: result.ast.nodes[result.ast.root]?.kind } : null;
      cache.set(name, decoded);
      return decoded;
    } catch (error) {
      unavailable = true;
      reportFailure(error instanceof Error ? error.message : String(error));
      return null;
    }
  };
};
