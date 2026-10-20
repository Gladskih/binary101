import names from "./relocation-names.generated.json" with { type: "json" };

// Full numeric ELF_RELOC definitions from LLVM llvmorg-23.1.3 (26 machines).
// https://github.com/llvm/llvm-project/tree/llvmorg-23.1.3/llvm/include/llvm/BinaryFormat/ELFRelocs
// JSON contains data only; unknown/vendor types keep their numeric identity.
const typeName = (machine: number, type: number): string =>
  (names as Record<number, Record<number, string>>)[machine]?.[type] ??
    `machine ${machine}, type ${type}`;

export const elfRelocationTypeName = (machine: number, type: number): string => {
  // LLVM ELFFile::getRelocationTypeName: MIPS N64 packs three operations.
  if (machine === 8 && type > 0xff) {
    const operations = [type & 0xff, type >>> 8 & 0xff, type >>> 16 & 0xff]
      .map(operation => typeName(machine, operation)).join(" / ");
    return operations + (type >>> 24 ? ` (special symbol ${type >>> 24})` : "");
  }
  // SPARC V9 ELF64_R_TYPE_ID is the low byte; TYPE_DATA is signed 24-bit.
  // https://docs.oracle.com/cd/E19683-01/817-3677/chapter6-54839/index.html
  if (machine === 43 && type > 0xff) return `${typeName(machine, type & 0xff)} (type data ${type >> 8})`;
  return typeName(machine, type);
};
