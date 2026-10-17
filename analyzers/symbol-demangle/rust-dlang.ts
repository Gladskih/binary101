import type { Ast as RustAst, Demangler as RustDemangler } from "llvm-rust-demangle";
import type { Ast as DlangAst, Demangler as DlangDemangler } from "llvm-dlang-demangle";
import { loadRustDemangler, loadDlangDemangler } from "#rust-dlang-demangler-loader";
import type { SymbolName } from "./name-decoder.js";

// D ABI special names represent data. A plain QualifiedName followed by Z does not
// prove a data object; Main is executable. Rust paths encode functions and statics
// alike, so their namespaces and any generic FunctionType must not classify a symbol.
// https://dlang.org/spec/abi.html#name_mangling
// https://rust-lang.github.io/rfcs/2603-rust-symbol-name-mangling-v0.html
const dlangDataSpecials = new Set(["Initializer", "VTable", "ClassInfo", "Interface", "ModuleInfo"]);

const dlangData = (ast: DlangAst | RustAst): boolean => {
  const root = ast.nodes[ast.root];
  if (root?.kind !== "Symbol") return false;
  const mangled = root.children.map(id => ast.nodes[id]).find(node => node?.kind === "MangledName");
  return !!mangled && (mangled.children.some(id => ast.nodes[id]?.kind === "Type") ||
    ast.nodes.some(node => node.kind === "IdentifierValue" &&
      node.special != null && dlangDataSpecials.has(node.special)));
};

const createGrammarDecoder = (
  reportFailure: (message: string) => void, loadDemangler: () => Promise<RustDemangler | DlangDemangler>,
  present: (result: ReturnType<RustDemangler["demangleWithText"]> |
    ReturnType<DlangDemangler["demangleWithText"]>) => SymbolName | null
) => {
  let pending: Promise<RustDemangler | DlangDemangler> | undefined;
  let unavailable = false;
  const cache = new Map<string, Promise<SymbolName | null>>();
  return (name: string): Promise<SymbolName | null> => {
    if (unavailable) return Promise.resolve(null);
    const cached = cache.get(name);
    if (cached) return cached;
    const decoded = (async () => {
      try {
        pending ??= loadDemangler();
        const result = (await pending).demangleWithText(name);
        if (result.status === "error" || result.status === "limit") {
          throw new Error(result.warnings.join("; ") || result.status);
        }
        return present(result);
      } catch (error) {
        if (!unavailable) {
          unavailable = true;
          reportFailure(error instanceof Error ? error.message : String(error));
        }
        return null;
      }
    })();
    cache.set(name, decoded);
    return decoded;
  };
};

export const createRustDlangNameDecoder = (
  reportFailure: (message: string) => void,
  loadRust: () => Promise<RustDemangler> = loadRustDemangler,
  loadDlang: () => Promise<DlangDemangler> = loadDlangDemangler
) => {
  const rust = createGrammarDecoder(message => reportFailure("Rust v0: " + message), loadRust,
    result => result.status === "success"
      ? { text: result.text, language: "Rust v0", symbolKind: undefined } : null);
  const dlang = createGrammarDecoder(message => reportFailure("D: " + message), loadDlang,
    result => result.status === "success" ? { text: result.text, language: "D",
      symbolKind: dlangData(result.ast) ? "DlangData" : undefined } : null);
  return (name: string | undefined): Promise<SymbolName | null> => {
    if (name?.startsWith("_R")) return rust(name);
    if (name?.startsWith("_D")) return dlang(name);
    return Promise.resolve(null);
  };
};
