import type { FileRangeReader } from "../file-range-reader.js";
import type { ElfBinaryLayout, ElfSymbolRecord } from "./binary-layout-types.js";
import type { ElfSectionHeader } from "./types.js";
import { createElfStringTableReader } from "./string-table.js";
import { createElfDynsymBindingValidator } from "./dynamic-symbol-validation.js";
import { type createElfGnuHashSymbolValidator, ELF_GNU_HASH_SEED, extendElfGnuHash } from "./hash-symbols.js";
import { type createElfSysvHashSymbolValidator, extendElfSysvHash } from "./sysv-hash.js";
import type { ElfDataRange } from "./virtual-data.js";

export type ElfDynamicSymbolRange = ElfDataRange & {
  reader?: FileRangeReader; storedOffset?: number;
  section?: ElfSectionHeader; truncated?: boolean;
};
export type ElfDynamicSymbolTables = {
  symtab: ElfDynamicSymbolRange; strtab: ElfDynamicSymbolRange | null;
};
export type ElfSymbolHashValidators = {
  gnu: ReturnType<typeof createElfGnuHashSymbolValidator>;
  sysv: ReturnType<typeof createElfSysvHashSymbolValidator>;
};
type IndexedRecord = { index: number; record: ElfSymbolRecord };
type SymbolNameHash = {
  seed: number;
  value: number;
  extend: (hash: number, bytes: Uint8Array) => number;
  check: (index: number, hash: number) => void;
};

const isDisplayable = (record: ElfSymbolRecord): boolean =>
  // NOTYPE, OBJECT, FUNC, COMMON, TLS (gABI 5.3), GNU_IFUNC (glibc elf.h).
  [0, 1, 2, 5, 6, 10].includes(record.info & 0x0f);

export const readElfDynamicSymbolRecords = async (
  symtab: ElfDynamicSymbolRange, layout: ElfBinaryLayout, issues: string[], reader: FileRangeReader,
  hashes: ElfSymbolHashValidators
): Promise<IndexedRecord[]> => {
  const records: IndexedRecord[] = [];
  const stride = layout.symbolEntrySize;
  const count = Math.floor(symtab.size / stride);
  const binding = createElfDynsymBindingValidator(symtab.section?.info, issues);
  const aligned = symtab.size % stride === 0;
  if (!aligned) issues.push(`.dynsym size is not aligned to entry size (${stride} bytes).`);
  let complete = aligned && !symtab.truncated;
  for (let index = 0; index < count; index += 1) {
    const record = layout.readSymbol(await reader.read(symtab.offset + index * stride, stride));
    if (!record) {
      issues.push(`Dynamic symbol #${index} is truncated.`);
      complete = false;
      break;
    }
    binding.record(index, record);
    if (isDisplayable(record) || hashes.gnu?.claims(index) || hashes.sysv?.claims(index)) {
      records.push({ index, record });
    }
  }
  binding.finish(complete ? count : undefined);
  if (complete) hashes.gnu?.finish(count);
  // Follow .dynstr offsets in order to avoid repeatedly reloading file-reader windows.
  return records.sort((left, right) => left.record.nameOffset - right.record.nameOffset);
};

export const createElfDynamicSymbolNameReader = (
  strtab: ElfDynamicSymbolRange | null, reader: FileRangeReader, issues: string[],
  { gnu, sysv }: ElfSymbolHashValidators
) => {
  const hashes: SymbolNameHash[] = [];
  if (gnu) hashes.push({ seed: ELF_GNU_HASH_SEED, value: ELF_GNU_HASH_SEED,
    extend: extendElfGnuHash, check: gnu.check });
  if (sysv) hashes.push({ seed: 0, value: 0, extend: extendElfSysvHash, check: sysv.check });
  let previousOffset: number | undefined;
  const readName = createElfStringTableReader(strtab?.reader ?? reader, strtab, issues, bytes => {
    for (const hash of hashes) hash.value = hash.extend(hash.value, bytes);
  });
  return async ({ index, record }: IndexedRecord): Promise<string | null> => {
    // Equal offsets are adjacent and the string reader reuses their decoded name.
    if (record.nameOffset !== previousOffset) {
      for (const hash of hashes) hash.value = hash.seed;
      previousOffset = record.nameOffset;
    }
    const name = await readName(record.nameOffset);
    if (name != null) {
      for (const hash of hashes) hash.check(index, hash.value);
    }
    return isDisplayable(record) ? name : null;
  };
};
