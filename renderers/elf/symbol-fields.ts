// Arm ELF and RISC-V psABI reserve bit 7 of st_other for a variant calling convention.
// https://github.com/ARM-software/abi-aa/blob/main/aaelf64/aaelf64.rst#symbol-table
// https://riscv-non-isa.github.io/riscv-elf-psabi-doc/
export const elfSymbolVisibilityText = (
  visibility: string, other: number, machine: number
): string => {
  const extra = other & ~3;
  if (!extra) return visibility;
  const variant = machine === 183 ? "VARIANT_PCS" : machine === 243 ? "VARIANT_CC" : "";
  const detail = variant && (extra & 0x80) ? ` · ${variant}` : "";
  return `${visibility}${detail} · st_other 0x${other.toString(16)}`;
};

// https://gabi.xinuos.com/elf/05-symtab.html#symbol-value
export const elfSymbolValueHelp = (objectType: number): string =>
  objectType === 1
    ? "st_value is usually the offset within the defining section. COMMON uses it for alignment. ABS holds an absolute value."
    : "st_value is usually a link-time virtual address. TLS symbols use an offset in the module TLS block. ABS holds an absolute value.";

export const elfSymbolVersionHelp = "A double @ marks a default version definition. " +
  "A single @ marks a required version or a non-default definition.";
