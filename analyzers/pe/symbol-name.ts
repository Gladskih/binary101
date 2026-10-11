import type { Demangler as MsvcDemangler } from "llvm-msvc-demangle";
import type { Demangler as ItaniumDemangler } from "llvm-itanium-demangle";
import { loadMsvcDemangler } from "#msvc-demangler-loader";
import { loadItaniumDemangler } from "#itanium-demangler-loader";
import { createMsvcSymbolNameDecoder } from "./msvc-demangle/symbol-name.js";
import { createItaniumNameDecoder } from "../itanium-demangle/name-decoder.js";

export type PeSymbolName = { text: string; symbolKind: string | undefined };

export const createPeSymbolNameDecoder = (
  reportFailure: (message: string) => void,
  loadMsvc: () => Promise<MsvcDemangler> = loadMsvcDemangler,
  loadItanium: () => Promise<ItaniumDemangler> = loadItaniumDemangler
) => {
  const microsoft = createMsvcSymbolNameDecoder(reportFailure, loadMsvc);
  const itanium = createItaniumNameDecoder(reportFailure, loadItanium);
  return (name: string | undefined): Promise<PeSymbolName | null> =>
    name?.startsWith("_Z") ? itanium.symbol(name) : microsoft(name);
};
