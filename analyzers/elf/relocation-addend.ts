import type { FileRangeReader } from "../file-range-reader.js";
import { ELF_MACHINE_ID } from "./abi-constants.js";
import type { ElfRelocationOperation } from "./relocation-operation.js";
import type { ElfRelocation, ElfRelocationImage, ElfRelocationTable, ElfRelocationTarget } from "./relocation-types.js";

// i386 uses the stored word in the REL forms of these operations.
// https://github.com/bminor/glibc/blob/master/sysdeps/i386/dl-machine.h
const storedWordOperations = new Set<ElfRelocationOperation>(["relative", "absolute", "pc-relative", "resolver"]);

export const readElfStoredRelocationAddend = async (
  reader: FileRangeReader, elf: ElfRelocationImage, table: ElfRelocationTable,
  entry: ElfRelocation, operation: ElfRelocationOperation, target: ElfRelocationTarget | null
): Promise<bigint | undefined> => {
  if (elf.header.machine !== ELF_MACHINE_ID.I386 || (table.encoding !== "REL" && table.encoding !== "ANDROID_REL") ||
    !storedWordOperations.has(operation) || target?.fileOffset == null) return undefined;
  if (entry.addend != null) return undefined;
  const view = await reader.read(Number(target.fileOffset), 4);
  return view.byteLength === 4 ? BigInt(view.getUint32(0, elf.littleEndian)) : undefined;
};
