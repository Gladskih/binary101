import type { SanitizerDependency, SanitizerEvidence, SanitizerSymbol } from "./types.js";
import { SANITIZER_ABI_SYMBOLS } from "./abi-catalog.js";
import { identifySanitizerLibrary } from "./runtime-libraries.js";

const collectSymbolEvidence = (symbols: Iterable<SanitizerSymbol>,
  abiName: (name: string) => string): SanitizerEvidence[] => {
  // Mutate only local indexes: one linear scan, no repeated symbol-table decoding or name scans.
  const evidence = new Map<string, SanitizerEvidence>();
  const names = new Map<string, Set<string>>();
  for (const symbol of symbols) {
    const name = abiName(symbol.name);
    const tool = SANITIZER_ABI_SYMBOLS.get(name);
    if (!tool) continue;
    const group = `${tool}:${symbol.kind}`;
    const distinct = names.get(group) ?? new Set<string>();
    distinct.add(name);
    names.set(group, distinct);
    evidence.set(JSON.stringify([tool, symbol.kind, symbol.source, symbol.name]),
      { tool, ...symbol });
  }
  // Conservative policy: two distinct known ABI names of one family and evidence kind.
  // A definition plus an undefined reference cannot corroborate each other.
  return [...evidence.values()].filter(row => names.get(`${row.tool}:${row.kind}`)!.size >= 2);
};

export const analyzeSanitizerEvidence = (
  dependencies: Iterable<SanitizerDependency>, symbols: Iterable<SanitizerSymbol>,
  abiName: (name: string) => string = name => name
): SanitizerEvidence[] => {
  const evidence = new Map<string, SanitizerEvidence>();
  for (const dependency of dependencies) {
    const tool = identifySanitizerLibrary(dependency.name);
    if (tool) evidence.set(JSON.stringify([dependency.source, dependency.name]),
      { tool, kind: "dependency", ...dependency });
  }
  return [...evidence.values(), ...collectSymbolEvidence(symbols, abiName)];
};
