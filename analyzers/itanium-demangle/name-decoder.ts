import type { AstNode, Demangler, DemangleWithTextResult } from "llvm-itanium-demangle";
import { loadItaniumDemangler } from "#itanium-demangler-loader";

export type ItaniumName = { text: string; symbolKind: "ItaniumData" | undefined };

// Positive data encodings only. Thunks and TLS wrapper routines are executable.
// LLVM ItaniumDemangle.h parseEncoding/parseSpecialName; Itanium ABI 5.1.2, 5.1.4.
// https://itanium-cxx-abi.github.io/cxx-abi/abi.html#mangling-special
const dataNames = new Set<AstNode["kind"]>(["NameType", "NestedName", "QualifiedName",
  "NameWithTemplateArgs", "LocalName", "AbiTagAttr", "ModuleEntity", "StructuredBindingName",
  "CtorVtableSpecialName"]);
const dataSpecialNames = new Set(["vtable for ", "VTT for ", "typeinfo for ",
  "typeinfo name for ", "guard variable for ", "reference temporary for ",
  "template parameter object for "]);

const decodedName = (result: DemangleWithTextResult): ItaniumName | null => {
  if (result.status === "error" || result.status === "limit") {
    throw new Error(result.warnings.join("; ") || result.status);
  }
  if (result.status !== "success") return null;
  const root = result.ast.nodes[result.ast.root];
  return { text: result.text, symbolKind: root && (dataNames.has(root.kind) ||
    (root.kind === "SpecialName" && dataSpecialNames.has(root.special)))
    ? "ItaniumData" : undefined };
};

export const createItaniumNameDecoder = (
  reportFailure: (message: string) => void,
  loadDemangler: () => Promise<Demangler> = loadItaniumDemangler
) => {
  let pending: Promise<Demangler> | undefined;
  let unavailable = false;
  // Cache promises so concurrent aliases share the parse as well as WASM initialization.
  const caches = { symbol: new Map<string, Promise<ItaniumName | null>>(),
    type: new Map<string, Promise<ItaniumName | null>>() };
  const decode = async (cache: Map<string, Promise<ItaniumName | null>>, name: string,
    parse: (api: Demangler) => DemangleWithTextResult) => {
    if (unavailable) return null;
    const cached = cache.get(name);
    if (cached) return cached;
    const result = (async () => {
      try {
        pending ??= loadDemangler();
        return decodedName(parse(await pending));
      } catch (error) {
        if (!unavailable) {
          unavailable = true;
          reportFailure(error instanceof Error ? error.message : String(error));
        }
        return null;
      }
    })();
    cache.set(name, result);
    return result;
  };
  return {
    symbol: (name: string | undefined): Promise<ItaniumName | null> =>
      name?.startsWith("_Z") ? decode(caches.symbol, name, api => api.demangleWithText(name))
        : Promise.resolve(null),
    type: (name: string): Promise<ItaniumName | null> =>
      decode(caches.type, name, api => api.demangleTypeWithText(name))
  };
};
