import type { ElfHashTable } from "./hash-types.js";

type GnuTable = Extract<ElfHashTable, { kind: "gnu" }>;
type HashProblem = "chain" | "bloom" | "bucket";

// GNU hash uses the bytes of the NUL-terminated string.
// https://github.com/bminor/glibc/blob/master/sysdeps/generic/dl-new-hash.h
export const ELF_GNU_HASH_SEED = 5381;
export const extendElfGnuHash = (hash: number, bytes: Uint8Array): number => {
  let value = hash;
  for (const byte of bytes) value = (Math.imul(value, 33) + byte) >>> 0;
  return value;
};

const bucketEnds = (table: GnuTable): Map<number, number> => {
  const starts = new Set(table.buckets.filter(Boolean));
  const ends = new Map<number, number>();
  let end = -1;
  for (let index = table.chains.length - 1; index >= 0; index -= 1) {
    const symbol = index + table.symbolOffset;
    if (table.chains[index]! & 1) end = symbol;
    if (starts.has(symbol)) ends.set(symbol, end);
  }
  return ends;
};

const bloomMatches = (table: GnuTable, hash: number, wordBits: 32 | 64): boolean => {
  const word = Math.floor(hash / wordBits) & (table.bloom.length - 1);
  const mask = (1n << BigInt(hash % wordBits)) | (1n << BigInt((hash >>> table.bloomShift) % wordBits));
  return (table.bloom[word]! & mask) === mask;
};

// glibc uses the bucket selected by the raw-name hash and follows its chain
// through the first word with the low bit set.
// https://github.com/bminor/glibc/blob/master/elf/dl-lookup.c
const prepareHashCheck = (table: GnuTable, wordBits: 32 | 64) => {
  const ends = bucketEnds(table);
  const reported = new Set<HashProblem>();
  const report = (problem: HashProblem, message: string): void => {
    if (reported.has(problem)) return;
    reported.add(problem);
    table.issues.push(message);
  };
  return {
    claims: (index: number) => index >= table.symbolOffset &&
      index - table.symbolOffset < table.chains.length,
    finish(count: number): void {
      // Every symbol from symndx to the end of .dynsym has a chain word.
      // https://sourceware.org/pipermail/binutils/2006-October/049450.html
      const expected = count - table.symbolOffset;
      if (expected !== table.chains.length) {
        table.issues.push(`GNU hash chain length (${table.chains.length}) disagrees with ` +
          `dynamic symbol count (${count}) and symbol offset (${table.symbolOffset}).`);
      }
    },
    check(index: number, hash: number): void {
      const chain = table.chains[index - table.symbolOffset]!;
      const bucket = hash % table.buckets.length;
      const start = table.buckets[bucket]!;
      if ((chain & ~1) !== (hash & ~1)) {
        report("chain", `GNU hash does not match dynamic symbol #${index}.`);
      }
      if (!bloomMatches(table, hash, wordBits)) {
        report("bloom", `GNU Bloom filter would reject dynamic symbol #${index}.`);
      }
      if (!start || index < start || index > (ends.get(start) ?? -1)) {
        report("bucket", `Dynamic symbol #${index} is unreachable from GNU hash bucket ${bucket}.`);
      }
    }
  };
};

export const createElfGnuHashSymbolValidator = (tables: ElfHashTable[], wordBits: 32 | 64) => {
  const checks = tables.flatMap(table => table.kind === "gnu" && !table.issues.length &&
    table.chains.length && table.buckets.length && table.bloom.length ? [prepareHashCheck(table, wordBits)] : []);
  if (!checks.length) return undefined;
  return {
    claims: (index: number) => checks.some(check => check.claims(index)),
    check(index: number, hash: number): void {
      for (const check of checks) {
        if (check.claims(index)) check.check(index, hash);
      }
    },
    finish(count: number): void {
      for (const check of checks) check.finish(count);
    }
  };
};
