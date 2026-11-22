import { ELF_FILE_TYPE, ELF_MACHINE_ID, ELF_SECTION_FLAG, ELF_SECTION_TYPE } from "./abi-constants.js";
import type { ElfRelocationImage, ElfRelocationTable } from "./relocation-types.js";

export type ElfRelocationOperation = "relative" | "global-data" | "jump-slot" | "resolver" |
  "copy" | "absolute" | "absolute64" | "pc-relative" | "tls-descriptor" | "relative64";

type RuntimeImage = Pick<ElfRelocationImage, "header" | "sections">;
type RelocationMachine = Pick<ElfRelocationImage, "header" | "is64">;
type OperationTable = Readonly<Record<number, ElfRelocationOperation>>;

// The processor's dynamic relocation operations and write sizes.
// https://gitlab.com/x86-psABIs/x86-64-ABI/-/raw/master/x86-64-ABI/abi.pdf
// https://github.com/ARM-software/abi-aa/blob/main/aaelf64/aaelf64.rst#dynamic-relocations
// https://github.com/bminor/glibc/blob/master/sysdeps/i386/dl-machine.h
const i386: OperationTable = {
  1: "absolute", 2: "pc-relative", 5: "copy", 6: "global-data", 7: "jump-slot", 8: "relative",
  41: "tls-descriptor", 42: "resolver"
};
const x86_64: OperationTable = {
  1: "absolute64", 5: "copy", 6: "global-data", 7: "jump-slot", 8: "relative",
  36: "tls-descriptor", 37: "resolver", 38: "relative64"
};
const aarch64: OperationTable = {
  257: "absolute64", 1024: "copy", 1025: "global-data", 1026: "jump-slot", 1027: "relative",
  1031: "tls-descriptor", 1032: "resolver"
};
const aarch64P32: OperationTable = {
  180: "copy", 181: "global-data", 182: "jump-slot", 183: "relative",
  187: "tls-descriptor", 188: "resolver"
};
const elf32Operations = new Map<number, OperationTable>([
  [ELF_MACHINE_ID.I386, i386], [ELF_MACHINE_ID.X86_64, x86_64], [ELF_MACHINE_ID.AARCH64, aarch64P32]
]);
const elf64Operations = new Map<number, OperationTable>([
  [ELF_MACHINE_ID.X86_64, x86_64], [ELF_MACHINE_ID.AARCH64, aarch64]
]);

export const elfRuntimeRelocationOperation = (
  elf: RelocationMachine, type: number | null
): ElfRelocationOperation | undefined =>
  (elf.is64 ? elf64Operations : elf32Operations).get(elf.header.machine)?.[type ?? -1];

export const elfRuntimeRelocationWriteSize = (
  elf: RelocationMachine, operation: ElfRelocationOperation | undefined
): bigint | undefined => {
  if (!operation || operation === "copy") return undefined;
  if (operation === "relative64" || operation === "absolute64") return 8n;
  const pointerWidth = elf.is64 ? 8n : 4n;
  return operation === "tls-descriptor" ? 2n * pointerWidth : pointerWidth;
};

export const isElfRuntimeRelocationTable = (elf: RuntimeImage, table: ElfRelocationTable): boolean => {
  if (elf.header.type !== ELF_FILE_TYPE.EXEC && elf.header.type !== ELF_FILE_TYPE.DYN) return false;
  if (table.sources.some(source => source.startsWith("DT_"))) return true;
  const section = elf.sections.find(section => section.index === table.sectionIndex);
  if (!section || !(section.flags & ELF_SECTION_FLAG.ALLOC)) return false;
  return table.encoding === "RELR" || table.encoding === "AUTH_RELR" ||
    elf.sections.some(section => section.index === table.symbolTableIndex && section.type === ELF_SECTION_TYPE.DYNSYM);
};
