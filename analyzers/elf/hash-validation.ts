import type { ElfHashTable } from "./hash-types.js";

// System V hash traversal and GNU hash termination: gABI 8.5 and glibc dl-lookup.c.
// https://gabi.xinuos.com/elf/08-dynamic.html#hash-table
// https://raw.githubusercontent.com/bminor/glibc/master/elf/dl-lookup.c
const validateSysvChains = (table: ElfHashTable): void => {
  const complete = new Set<number>();
  for (const bucket of table.buckets) {
    const path = new Set<number>();
    let index = bucket;
    while (index && !complete.has(index)) {
      if (index >= table.chains.length) {
        table.issues.push(`Hash symbol index ${index} is outside the chain table.`);
        break;
      }
      if (path.has(index)) {
        table.issues.push(`Hash chain has a cycle at symbol #${index}.`);
        break;
      }
      path.add(index);
      index = table.chains[index]!;
    }
    for (const item of path) complete.add(item);
  }
};

export const validateElfHashTable = (table: ElfHashTable): void => {
  if (table.kind === "sysv") {
    validateSysvChains(table);
    return;
  }
  if (!table.bloom.length || (table.bloom.length & (table.bloom.length - 1)) !== 0) {
    table.issues.push("GNU hash Bloom word count must be a nonzero power of two.");
  }
  if (table.bloomShift >= 32) table.issues.push("GNU hash Bloom shift exceeds the 32-bit hash width.");
  validateGnuBuckets(table);
};

const validateGnuBuckets = (table: Extract<ElfHashTable, { kind: "gnu" }>): void => {
  const ends = new Set<number>();
  for (let index = 0; index < table.chains.length; index += 1) {
    if (table.chains[index]! & 1) ends.add(index);
  }
  let previous = -1;
  for (const bucket of table.buckets.filter(value => value !== 0)) {
    const start = bucket - table.symbolOffset;
    if (start < 0 || start >= table.chains.length) {
      table.issues.push(`GNU hash bucket ${bucket} is outside the chain table.`);
    } else if (overlappingChain(start, previous, ends)) {
      table.issues.push(`GNU hash bucket ${bucket} overlaps a preceding chain or is out of order.`);
    }
    previous = start;
  }
  if (table.chains.length && !ends.has(table.chains.length - 1)) {
    table.issues.push("GNU hash chain is not terminated.");
  }
};

const overlappingChain = (start: number, previous: number, ends: Set<number>): boolean =>
  start <= previous || (start > 0 && !ends.has(start - 1));
