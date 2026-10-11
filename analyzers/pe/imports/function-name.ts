"use strict";

import { createMsvcSymbolNameDecoder } from "../msvc-demangle/symbol-name.js";
import type { Demangler } from "llvm-msvc-demangle";
import { loadMsvcDemangler } from "#msvc-demangler-loader";

// Keep linker names intact; presentation follows each parsed function through lazy rendering.
const displayNames = new WeakMap<{ name?: string }, string>();
export type DecodeImportFunctionName = (fn: { name?: string }) => Promise<void>;

export const createImportFunctionNameDecoder = (
  addWarning: (message: string) => void,
  loadDemangler: () => Promise<Demangler> = loadMsvcDemangler
): DecodeImportFunctionName => {
  const decode = createMsvcSymbolNameDecoder(
    message => addWarning("Import name demangling unavailable: " + message), loadDemangler
  );
  return async fn => {
    const decoded = await decode(fn.name);
    if (decoded !== null) displayNames.set(fn, decoded.text);
  };
};

export const getImportFunctionDisplayName = (fn: { name?: string }): string =>
  displayNames.get(fn) ?? fn.name ?? "";
