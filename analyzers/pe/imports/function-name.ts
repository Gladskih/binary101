"use strict";

import { createPeSymbolNameDecoder } from "../symbol-name.js";
import type { Demangler } from "llvm-msvc-demangle";
import type { Demangler as ItaniumDemangler } from "llvm-itanium-demangle";
import { loadMsvcDemangler } from "#msvc-demangler-loader";
import { loadItaniumDemangler } from "#itanium-demangler-loader";

// Keep linker names intact; presentation follows each parsed function through lazy rendering.
const displayNames = new WeakMap<{ name?: string }, string>();
export type DecodeImportFunctionName = (fn: { name?: string }) => Promise<void>;

export const createImportFunctionNameDecoder = (
  addWarning: (message: string) => void,
  loadDemangler: () => Promise<Demangler> = loadMsvcDemangler,
  loadItanium: () => Promise<ItaniumDemangler> = loadItaniumDemangler
): DecodeImportFunctionName => {
  const decode = createPeSymbolNameDecoder(
    message => addWarning("Import name demangling unavailable: " + message), loadDemangler, loadItanium
  );
  return async fn => {
    const decoded = await decode(fn.name);
    if (decoded !== null) displayNames.set(fn, decoded.text);
  };
};

export const getImportFunctionDisplayName = (fn: { name?: string }): string =>
  displayNames.get(fn) ?? fn.name ?? "";
