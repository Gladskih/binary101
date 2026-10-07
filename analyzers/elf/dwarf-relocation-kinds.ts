import type { ElfDwarfRelocationKind } from "./dwarf-relocation-types.js";

// AMD64 psABI Table 4.9: https://refspecs.linuxbase.org/elf/x86_64-abi-0.99.pdf
// AArch64 data relocations: https://github.com/ARM-software/abi-aa/blob/main/aaelf64/aaelf64.rst
// RISC-V table: https://github.com/riscv-non-isa/riscv-elf-psabi-doc/blob/master/riscv-elf.adoc
const absolute = (width: number, overflow: ElfDwarfRelocationKind["overflow"]): ElfDwarfRelocationKind =>
  ({ width, overflow, operation: "absolute" });
const relative = (width: number, overflow: ElfDwarfRelocationKind["overflow"]): ElfDwarfRelocationKind =>
  ({ width, overflow, operation: "relative" });

const x86: Readonly<Record<number, ElfDwarfRelocationKind>> = {
  1: absolute(8, "truncate"), 2: relative(4, "signed"),
  10: absolute(4, "unsigned"), 11: absolute(4, "signed"),
  12: absolute(2, "unsigned"), 13: relative(2, "signed"),
  14: absolute(1, "unsigned"), 15: relative(1, "signed"), 24: relative(8, "truncate")
};
const aarch64: Readonly<Record<number, ElfDwarfRelocationKind>> = {
  257: absolute(8, "truncate"), 258: absolute(4, "mixed"), 259: absolute(2, "mixed"),
  260: relative(8, "truncate"), 261: relative(4, "signed"), 262: relative(2, "signed")
};
const riscv: Readonly<Record<number, ElfDwarfRelocationKind>> = {
  1: absolute(4, "truncate"), 2: absolute(8, "truncate"), 57: relative(4, "signed"),
  33: { width: 1, operation: "add", overflow: "truncate" },
  34: { width: 2, operation: "add", overflow: "truncate" },
  35: { width: 4, operation: "add", overflow: "truncate" },
  36: { width: 8, operation: "add", overflow: "truncate" },
  37: { width: 1, operation: "subtract", overflow: "truncate" },
  38: { width: 2, operation: "subtract", overflow: "truncate" },
  39: { width: 4, operation: "subtract", overflow: "truncate" },
  40: { width: 8, operation: "subtract", overflow: "truncate" },
  54: absolute(1, "truncate"), 55: absolute(2, "truncate"), 56: absolute(4, "truncate")
};
const i386: Readonly<Record<number, ElfDwarfRelocationKind>> = {
  1: absolute(4, "truncate"), 2: relative(4, "truncate")
};

export const elfDwarfRelocationKind = (machine: number, type: number): ElfDwarfRelocationKind | null =>
  ({ 3: i386, 62: x86, 183: aarch64, 243: riscv } as
    Readonly<Record<number, Readonly<Record<number, ElfDwarfRelocationKind>>>>)[machine]?.[type] ?? null;
