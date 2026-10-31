import type { ResourceSymbol } from "./types.js";

export interface RccArraySymbols {
  tree: ResourceSymbol;
  names: ResourceSymbol;
  data: ResourceSymbol;
}

// RCC emits these exact static array identifiers. Accept C/COFF decoration and
// Itanium local-name encoding, validating the encoded length before association.
// https://code.qt.io/cgit/qt/qtbase.git/tree/src/tools/rcc/rcc.cpp
const arrayName = (symbol: string): string | null => {
  const mangled = /^_ZL(\d+)(qt_resource_(?:struct|name|data))$/u.exec(symbol);
  if (mangled) return Number(mangled[1]) === mangled[2]!.length ? mangled[2]! : null;
  return /^_?qt_resource_(?:struct|name|data)$/u.test(symbol) ? symbol.replace(/^_/u, "") : null;
};

export const findRccArraySymbols = (symbols: ResourceSymbol[]): RccArraySymbols[] => {
  const groups = new Map<string, Map<string, ResourceSymbol[]>>();
  for (const symbol of symbols) {
    const name = arrayName(symbol.name);
    if (!name) continue;
    const group = groups.get(symbol.scope) ?? new Map<string, ResourceSymbol[]>();
    const matches = group.get(name) ?? [];
    matches.push(symbol);
    group.set(name, matches);
    groups.set(symbol.scope, group);
  }
  return [...groups.values()].flatMap(group => {
    const tree = group.get("qt_resource_struct");
    const names = group.get("qt_resource_name");
    const data = group.get("qt_resource_data");
    return tree?.length === 1 && names?.length === 1 && data?.length === 1
      ? [{ tree: tree[0]!, names: names[0]!, data: data[0]! }] : [];
  });
};
