import type { FileRangeReader } from "../file-range-reader.js";
import type { ElfByteOrder } from "./binary-layout-types.js";
import { ELF_INTEGER_READERS } from "./byte-order.js";
import type { ElfMipsOption, ElfMipsRegInfo } from "./mips-types.js";

// Elf_Mips_Options: 8-byte header; size includes header, ODK_REGINFO=1.
// https://raw.githubusercontent.com/llvm/llvm-project/main/llvm/include/llvm/Object/ELFTypes.h
export const readMipsOptions = async (
  reader: FileRangeReader, range: { offset: number; size: number }, order: ElfByteOrder,
  readRegInfo: (view: DataView, order: ElfByteOrder) => ElfMipsRegInfo | null, issues: string[]
): Promise<ElfMipsOption[]> => {
  const options: ElfMipsOption[] = [];
  const integers = ELF_INTEGER_READERS[order];
  let offset = 0;
  while (offset < range.size) {
    const view = await reader.read(range.offset + offset, Math.min(range.size - offset, 255));
    if (view.byteLength < 8 || view.getUint8(1) < 8 || view.getUint8(1) > view.byteLength) {
      issues.push("MIPS option has an invalid size or is truncated.");
      break;
    }
    const size = view.getUint8(1);
    const option: ElfMipsOption = { kind: view.getUint8(0), section: integers.u16(view, 2),
      info: integers.u32(view, 4) };
    if (option.kind === 1) {
      const registerInfo = readRegInfo(new DataView(view.buffer, view.byteOffset + 8, size - 8), order);
      if (registerInfo) option.registerInfo = registerInfo;
      else issues.push("MIPS REGINFO option payload is truncated.");
    } else issues.push(`MIPS option kind ${option.kind} has no decoded payload.`);
    options.push(option);
    offset += size;
    if (options.length === 100000) {
      issues.push("MIPS option count exceeds the 100000 entry limit.");
      break;
    }
  }
  return options;
};
