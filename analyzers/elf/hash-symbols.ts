import type { ElfHashTable } from "./hash-types.js";
import type { ElfDynamicSymbolInfo } from "./types.js";

// GNU hash and Bloom lookup: glibc dl-new-hash.h / dl-lookup.c.
// https://raw.githubusercontent.com/bminor/glibc/master/sysdeps/generic/dl-new-hash.h
// https://raw.githubusercontent.com/bminor/glibc/master/elf/dl-lookup.c
const gnuHash = (name: string): number => {
  let hash = 5381;
  for (const byte of new TextEncoder().encode(name)) hash = (Math.imul(hash, 33) + byte) >>> 0;
  return hash;
};

export const validateElfHashSymbols = (
  tables: ElfHashTable[], symbols: ElfDynamicSymbolInfo | null, wordBits: 32 | 64
): void => {
  if (!symbols) return;
  for (const table of tables.filter(item => item.kind === "gnu" && !item.issues.length)) {
    if (table.kind !== "gnu") continue;
    for (const symbol of [...symbols.importSymbols, ...symbols.exportSymbols]) {
      if (symbol.index < table.symbolOffset) continue;
      const hash = gnuHash(symbol.name);
      const chain = table.chains[symbol.index - table.symbolOffset];
      if (chain == null || (chain & ~1) !== (hash & ~1)) {
        table.issues.push(`GNU hash does not match dynamic symbol #${symbol.index}.`);
        continue;
      }
      const bloomIndex = Math.floor(hash / wordBits) & (table.bloom.length - 1);
      const mask = (1n << BigInt(hash % wordBits)) | (1n << BigInt((hash >>> table.bloomShift) % wordBits));
      if ((table.bloom[bloomIndex]! & mask) !== mask) {
        table.issues.push(`GNU Bloom filter would reject dynamic symbol #${symbol.index}.`);
      }
    }
  }
};
