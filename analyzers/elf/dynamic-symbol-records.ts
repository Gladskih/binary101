import type { FileRangeReader } from "../file-range-reader.js";
import type { ElfBinaryLayout, ElfSymbolRecord } from "./binary-layout-types.js";
import type { ElfSectionHeader } from "./types.js";
import { createElfStringTableReader } from "./string-table.js";
import { createElfDynsymBindingValidator } from "./dynamic-symbol-validation.js";
import { type createElfGnuHashSymbolValidator, ELF_GNU_HASH_SEED, extendElfGnuHash } from "./hash-symbols.js";

export type ElfDynamicSymbolRange = {
  offset: number; size: number; reader?: FileRangeReader; storedOffset?: number;
  section?: ElfSectionHeader; truncated?: boolean;
};
export type ElfDynamicSymbolTables = {
  symtab: ElfDynamicSymbolRange; strtab: ElfDynamicSymbolRange | null;
};
type HashValidator = ReturnType<typeof createElfGnuHashSymbolValidator>;
type IndexedRecord = { index: number; record: ElfSymbolRecord };

const isDisplayable = (record: ElfSymbolRecord): boolean =>
  // NOTYPE, OBJECT, FUNC, COMMON, TLS (gABI 5.3), GNU_IFUNC (glibc elf.h).
  [0, 1, 2, 5, 6, 10].includes(record.info & 0x0f);

export const readElfDynamicSymbolRecords = async (
  symtab: ElfDynamicSymbolRange, layout: ElfBinaryLayout, issues: string[], reader: FileRangeReader,
  hash: HashValidator
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
    if (isDisplayable(record) || hash?.claims(index)) records.push({ index, record });
  }
  binding.finish(complete ? count : undefined);
  if (complete) hash?.finish(count);
  // Follow .dynstr offsets in order to avoid repeatedly reloading file-reader windows.
  return records.sort((left, right) => left.record.nameOffset - right.record.nameOffset);
};

export const createElfDynamicSymbolNameReader = (
  strtab: ElfDynamicSymbolRange | null, reader: FileRangeReader, issues: string[], hash: HashValidator
) => {
  let nameHash = ELF_GNU_HASH_SEED;
  let previousOffset: number | undefined;
  const readName = createElfStringTableReader(strtab?.reader ?? reader, strtab, issues,
    hash ? bytes => { nameHash = extendElfGnuHash(nameHash, bytes); } : undefined);
  return async ({ index, record }: IndexedRecord): Promise<string | null> => {
    // Equal offsets are adjacent and the string reader reuses their decoded name.
    if (record.nameOffset !== previousOffset) {
      nameHash = ELF_GNU_HASH_SEED;
      previousOffset = record.nameOffset;
    }
    const name = await readName(record.nameOffset);
    if (name != null) hash?.check(index, nameHash);
    return isDisplayable(record) ? name : null;
  };
};
