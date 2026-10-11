import type { Demangler } from "llvm-itanium-demangle";
import { loadItaniumDemangler } from "#itanium-demangler-loader";
import { createItaniumNameDecoder } from "../itanium-demangle/name-decoder.js";
import type { ItaniumRttiAnalysis, ItaniumType } from "./types.js";

const typeNames = new WeakMap<ItaniumType, string>();

export const decodeItaniumRttiTypeNames = async (
  analysis: ItaniumRttiAnalysis, loadDemangler: () => Promise<Demangler> = loadItaniumDemangler
): Promise<void> => {
  const decoder = createItaniumNameDecoder(message => analysis.warnings.push(
    "Itanium RTTI name demangling unavailable: " + message), loadDemangler);
  for (const type of analysis.types) {
    const decoded = await decoder.type(type.name);
    if (decoded) typeNames.set(type, decoded.text);
  }
};

export const getItaniumRttiTypeName = (type: ItaniumType): string =>
  typeNames.get(type) ?? type.name;
