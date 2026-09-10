import type { DwarfCursor } from "../dwarf/cursor.js";
import type { ElfBuildAttribute } from "./attribute-types.js";

// ARM has two string tags below 32, and a two-part compatibility tag.
// https://raw.githubusercontent.com/llvm/llvm-project/main/llvm/lib/Support/ARMAttributeParser.cpp
// RISC-V uses integer even tags, NTBS odd tags:
// https://github.com/riscv-non-isa/riscv-elf-psabi-doc/blob/master/riscv-elf.adoc
export const readElfBuildAttribute = async (
  cursor: DwarfCursor, vendor: string
): Promise<ElfBuildAttribute | null> => {
  const tag = await cursor.uleb();
  if (tag == null) return null;
  noticeMandatoryTag(cursor, vendor, tag);
  if (vendor === "aeabi" && tag === 32n) {
    const flag = await cursor.uleb();
    const name = await cursor.cstring();
    return flag == null || name == null ? null : { tag, value: { flag, vendor: name } };
  }
  const value = stringAttribute(vendor, tag) ? await cursor.cstring() : await cursor.uleb();
  return value == null ? null : { tag, value };
};

const noticeMandatoryTag = (cursor: DwarfCursor, vendor: string, tag: bigint): void => {
  if (vendor === "riscv" && tag % 128n < 64n &&
      ![4n, 5n, 6n, 8n, 10n, 12n, 14n, 16n].includes(tag)) {
    cursor.notice(`Unknown mandatory RISC-V attribute tag ${tag}`);
  }
};

const stringAttribute = (vendor: string, tag: bigint): boolean =>
  vendor === "aeabi" ? tag === 4n || tag === 5n || (tag > 32n && (tag & 1n) !== 0n)
    : (tag & 1n) !== 0n;
