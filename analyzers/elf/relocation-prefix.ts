import { ELF_DYNAMIC_TAG, ELF_MACHINE_ID } from "./abi-constants.js";
import type { ElfRelocation, ElfRelocationImage, ElfRelocationTable } from "./relocation-types.js";
import type { ElfRelocationOperation } from "./relocation-operation.js";

// glibc elf/do-rel.h applies the advertised prefix through the relative-only handler.
// https://github.com/bminor/glibc/blob/master/elf/do-rel.h
// R_386_RELATIVE requires symbol index zero.
// https://docs.oracle.com/cd/E19120-01/open.solaris/819-0690/chapter6-54839/index.html
export const createElfRelativePrefixValidator = (
  elf: ElfRelocationImage, table: ElfRelocationTable, tags: Map<number, bigint>, issues: string[]
) => {
  const { machine } = elf.header;
  const { I386, X86_64, AARCH64 } = ELF_MACHINE_ID;
  if (machine !== I386 && machine !== X86_64 && machine !== AARCH64) return;
  if (machine === I386 && elf.is64) return;
  const rel = table.sources.includes("DT_REL") && machine === I386;
  const rela = table.sources.includes("DT_RELA");
  if (!rel && !rela) return;
  const count = tags.get(rel ? ELF_DYNAMIC_TAG.RELCOUNT : ELF_DYNAMIC_TAG.RELACOUNT);
  if (count == null || count <= 0n || count > BigInt(table.size / table.entrySize)) return;
  const tag = rel ? "DT_RELCOUNT" : "DT_RELACOUNT";
  let reported = false;
  return (ordinal: number, entry: ElfRelocation, operation: ElfRelocationOperation | undefined): void => {
    if (reported || ordinal >= Number(count)) return;
    const relative = operation === "relative" || operation === "relative64";
    if (relative && (machine !== I386 || entry.symbolIndex === 0)) return;
    const problem = relative ? `a nonzero symbol index (${entry.symbolIndex})` :
      `non-relative relocation type ${entry.type}`;
    issues.push(`${tag} prefix entry #${ordinal} has ${problem}.`);
    reported = true;
  };
};
