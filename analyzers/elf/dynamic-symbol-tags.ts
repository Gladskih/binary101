import { ELF_DYNAMIC_TAG } from "./abi-constants.js";
import { elfSingleDynamicTag } from "./dynamic-consistency.js";
import type { ElfDynamicTable } from "./dynamic-entries.js";

// gABI 5.1 and 8.3: DT_SYMENT gives the size of one Elf32_Sym or Elf64_Sym.
// https://gabi.xinuos.com/elf/08-dynamic.html#dynamic-section
const checkSymbolEntrySize = (table: ElfDynamicTable, expected: number, issues: string[]): boolean => {
  const declared = elfSingleDynamicTag(table.entries, ELF_DYNAMIC_TAG.SYMENT);
  if (declared === BigInt(expected)) return true;
  if (declared === null) issues.push("Conflicting DT_SYMENT values.");
  else if (declared !== undefined) issues.push(`DT_SYMENT is ${declared} bytes. Expected ${expected} bytes.`);
  else if (table.terminated) issues.push("ELF dynamic table is missing required DT_SYMENT.");
  return false;
};

export const elfDynamicSymbolTags = (table: ElfDynamicTable, entrySize: number, issues: string[]) => {
  const validSize = checkSymbolEntrySize(table, entrySize, issues);
  const symtabVaddr = elfSingleDynamicTag(table.entries, ELF_DYNAMIC_TAG.SYMTAB);
  if (symtabVaddr === null) issues.push("Conflicting DT_SYMTAB values.");
  const declaredSize = elfSingleDynamicTag(table.entries, ELF_DYNAMIC_TAG.SYMTABSZ);
  if (declaredSize === null) issues.push("Conflicting DT_SYMTABSZ values.");
  if (!validSize || symtabVaddr == null || declaredSize === null) return null;
  const strtabVaddr = elfSingleDynamicTag(table.entries, ELF_DYNAMIC_TAG.STRTAB);
  const strsz = elfSingleDynamicTag(table.entries, ELF_DYNAMIC_TAG.STRSZ);
  return strtabVaddr == null || strsz == null ? null : { symtabVaddr, strtabVaddr, strsz, entrySize, declaredSize };
};
