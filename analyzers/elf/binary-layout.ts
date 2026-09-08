import type { ElfBinaryLayout } from "./binary-layout-types.js";
import { createElf32Layout } from "./elf32-layout.js";
import { createElf64Layout } from "./elf64-layout.js";
import type { ElfParseResult } from "./types.js";

export const selectElfBinaryLayout = (
  elf: Pick<ElfParseResult, "is64" | "littleEndian">
): ElfBinaryLayout => {
  const byteOrder = elf.littleEndian ? "little" : "big";
  if (elf.is64) return createElf64Layout(byteOrder);
  return createElf32Layout(byteOrder);
};
