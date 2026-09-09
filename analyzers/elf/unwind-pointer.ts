import type { DwarfCursor } from "../dwarf/cursor.js";
import type { ElfUnwindPointer } from "./unwind-types.js";

// DW_EH_PE encodings: LSB 10.5.1 and LLVM's unwind address-space reader.
// https://refspecs.linuxfoundation.org/LSB_5.0.0/LSB-Core-generic/LSB-Core-generic/dwarfext.html
// https://raw.githubusercontent.com/llvm/llvm-project/main/libunwind/src/AddressSpace.hpp
const encodedInteger = async (
  cursor: DwarfCursor, format: number, addressSize: number
): Promise<bigint | null> => {
  if (format === 0) return cursor.unsigned(addressSize);
  if (format === 1) return cursor.uleb();
  if (format === 9) return cursor.sleb();
  const size = ({ 2: 2, 3: 4, 4: 8, 10: 2, 11: 4, 12: 8 } as Record<number, number>)[format];
  if (size == null) {
    cursor.fail(`Unsupported unwind pointer format 0x${format.toString(16)}`);
    return null;
  }
  const value = await cursor.unsigned(size);
  return value == null ? null : format >= 10 ? BigInt.asIntN(size * 8, value) : value;
};

export const readElfUnwindPointer = async (
  cursor: DwarfCursor, encoding: number, addressSize: number, sectionAddress: bigint
): Promise<ElfUnwindPointer | null> => {
  if (encoding === 0xff) return null;
  const application = encoding & 0x70;
  if (application !== 0 && application !== 0x10) {
    cursor.fail(`Unsupported unwind pointer base 0x${application.toString(16)}`);
    return null;
  }
  const position = cursor.position;
  const value = await encodedInteger(cursor, encoding & 15, addressSize);
  if (value == null) return null;
  return { address: value !== 0n && application === 0x10
    ? sectionAddress + BigInt(position) + value : value, indirect: (encoding & 0x80) !== 0 };
};
