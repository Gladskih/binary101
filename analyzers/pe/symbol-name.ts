import type { Demangler as MsvcDemangler } from "llvm-msvc-demangle";
import type { Demangler as ItaniumDemangler } from "llvm-itanium-demangle";
import { loadMsvcDemangler } from "#msvc-demangler-loader";
import { loadItaniumDemangler } from "#itanium-demangler-loader";
import { createMsvcSymbolNameDecoder } from "./msvc-demangle/symbol-name.js";
import { createSymbolNameDecoder } from "../symbol-demangle/name-decoder.js";

export type PeSymbolName = {
  text: string; symbolKind: string | undefined;
  language: "MSVC C++" | "Itanium C++" | "Rust v0" | "D";
};

export const createPeSymbolNameDecoder = (
  reportFailure: (message: string) => void,
  loadMsvc: () => Promise<MsvcDemangler> = loadMsvcDemangler,
  loadItanium: () => Promise<ItaniumDemangler> = loadItaniumDemangler
) => {
  const microsoft = createMsvcSymbolNameDecoder(reportFailure, loadMsvc);
  const symbols = createSymbolNameDecoder(reportFailure, loadItanium);
  return async (name: string | undefined): Promise<PeSymbolName | null> => {
    // i386 COFF adds a platform underscore to the ABI name. Preserve the original
    // linker name; strip only the extra prefix of recognized Rust/D grammars.
    // https://learn.microsoft.com/en-us/cpp/build/reference/decorated-names
    if (!name?.startsWith("?")) return symbols(
      name?.startsWith("__R") || name?.startsWith("__D") ? name.slice(1) : name);
    const decoded = await microsoft(name);
    return decoded && { ...decoded, language: "MSVC C++" };
  };
};
