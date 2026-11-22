import type { ElfHashTable } from "./hash-types.js";

type SysvTable = Extract<ElfHashTable, { kind: "sysv" }>;
const bucketOwners = new WeakMap<ElfHashTable, Map<number, number>>();

// gABI 8.5: hash the bytes passed to the loader, including non-UTF-8 bytes.
// https://gabi.xinuos.com/elf/08-dynamic.html#hash-table
export const extendElfSysvHash = (hash: number, bytes: Uint8Array): number => {
  let value = hash;
  for (const byte of bytes) {
    value = (value << 4) + byte;
    value = (value ^ ((value >>> 24) & 0xf0)) & 0x0fffffff;
  }
  return value;
};

export const validateElfSysvHashChains = (table: SysvTable): void => {
  const owners = new Map<number, number>();
  bucketOwners.set(table, owners);
  if (!table.buckets.length) table.issues.push("System V hash has no buckets.");
  table.buckets.forEach((head, bucket) => {
    for (let index = head; index; index = table.chains[index]!) {
      if (index >= table.chains.length) {
        table.issues.push(`Hash symbol index ${index} is outside the chain table.`);
        break;
      }
      const previous = owners.get(index);
      if (previous !== undefined) {
        table.issues.push(previous === bucket ? `Hash chain has a cycle at symbol #${index}.` :
          `System V hash buckets ${previous} and ${bucket} share the chain at symbol #${index}.`);
        break;
      }
      owners.set(index, bucket);
    }
  });
};

export const createElfSysvHashSymbolValidator = (tables: ElfHashTable[]) => {
  const checks = tables.flatMap(table => {
    if (table.issues.length) return [];
    const owners = bucketOwners.get(table);
    return owners?.size ? [{ table, owners, reported: false }] : [];
  });
  if (!checks.length) return undefined;
  return {
    claims: (index: number) => checks.some(({ owners }) => owners.has(index)),
    check(index: number, hash: number): void {
      for (const check of checks) {
        const bucket = check.owners.get(index);
        const expected = hash % check.table.buckets.length;
        if (bucket === undefined || bucket === expected || check.reported) continue;
        check.table.issues.push(`System V hash bucket ${bucket} contains dynamic symbol #${index}, ` +
          `whose name hashes to bucket ${expected}.`);
        check.reported = true;
      }
    }
  };
};
