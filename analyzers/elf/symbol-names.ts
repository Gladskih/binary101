import type { Demangler } from "llvm-itanium-demangle";
import { loadItaniumDemangler } from "#itanium-demangler-loader";
import type { Demangler as RustDemangler } from "llvm-rust-demangle";
import type { Demangler as DlangDemangler } from "llvm-dlang-demangle";
import { loadRustDemangler, loadDlangDemangler } from "#rust-dlang-demangler-loader";
import { createSymbolNameDecoder, type SymbolName } from "../symbol-demangle/name-decoder.js";
import type { ElfParseResult } from "./types.js";

// Sidecar presentation keeps linker identity intact for versions, hashes and relocations.
const displayNames = new WeakMap<{ name: string }, SymbolName>();

export const decodeElfSymbolNames = async (
  elf: ElfParseResult, loadDemangler: () => Promise<Demangler> = loadItaniumDemangler,
  loadRust: () => Promise<RustDemangler> = loadRustDemangler,
  loadDlang: () => Promise<DlangDemangler> = loadDlangDemangler
): Promise<void> => {
  const decoder = createSymbolNameDecoder(
    message => elf.issues.push("ELF symbol demangling unavailable: " + message),
    loadDemangler, loadRust, loadDlang);
  const decode = async (symbol: { name: string }): Promise<void> => {
    const decoded = await decoder(symbol.name);
    if (decoded) displayNames.set(symbol, decoded);
  };
  for (const symbol of elf.dynSymbols?.importSymbols ?? []) await decode(symbol);
  for (const symbol of elf.dynSymbols?.exportSymbols ?? []) await decode(symbol);
  for (const table of elf.symbolTables ?? []) {
    for (const symbol of table.entries) await decode(symbol);
  }
  for (const entry of elf.relocations?.entries ?? []) {
    if (entry.symbol) await decode(entry.symbol);
  }
};

export const getElfSymbolDisplayName = (symbol: { name: string }): string =>
  displayNames.get(symbol)?.text ?? symbol.name;

export const isElfSymbolData = (symbol: { name: string }): boolean =>
  displayNames.get(symbol)?.symbolKind != null;
