import type { Demangler as ItaniumDemangler } from "llvm-itanium-demangle";
import type { Demangler as RustDemangler } from "llvm-rust-demangle";
import type { Demangler as DlangDemangler } from "llvm-dlang-demangle";
import { loadItaniumDemangler } from "#itanium-demangler-loader";
import { loadRustDemangler, loadDlangDemangler } from "#rust-dlang-demangler-loader";
import { createItaniumNameDecoder } from "../itanium-demangle/name-decoder.js";
import { createRustDlangNameDecoder } from "./rust-dlang.js";

export type SymbolName = {
  text: string;
  language: "Itanium C++" | "Rust v0" | "D";
  symbolKind: "ItaniumData" | "DlangData" | undefined;
};

export const createSymbolNameDecoder = (
  reportFailure: (message: string) => void,
  loadItanium: () => Promise<ItaniumDemangler> = loadItaniumDemangler,
  loadRust: () => Promise<RustDemangler> = loadRustDemangler,
  loadDlang: () => Promise<DlangDemangler> = loadDlangDemangler
) => {
  const itanium = createItaniumNameDecoder(reportFailure, loadItanium);
  const rustDlang = createRustDlangNameDecoder(reportFailure, loadRust, loadDlang);
  return async (name: string | undefined): Promise<SymbolName | null> => {
    if (!name?.startsWith("_Z")) return rustDlang(name);
    const decoded = await itanium.symbol(name);
    return decoded && { ...decoded, language: "Itanium C++" };
  };
};
