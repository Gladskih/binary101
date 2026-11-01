import { COFF_SECTION_CHARACTERISTICS } from "../../coff/layout.js";
import { IMAGE_FILE_MACHINE_ARM64 } from "../../coff/machine.js";
import type { FileRangeReader } from "../../file-range-reader.js";
import type { PeWindowsCore } from "../types.js";
import type { EhImage } from "./types.js";
import { isRvaRange } from "../rva-mapping.js";

const mappedEhRange = (reader: FileRangeReader, core: PeWindowsCore, rva: number) => {
  if (!isRvaRange(rva, 1) || rva >= core.opt.SizeOfImage) return null;
  let section: PeWindowsCore["sections"][number] | undefined;
  let next = core.opt.SizeOfImage;
  // One scan supplies both the unique owner and the next overlap boundary;
  // no transient filter arrays or repeated section lookup for the same read.
  for (const candidate of core.sections) {
    if (candidate.virtualAddress > rva) next = Math.min(next, candidate.virtualAddress);
    else if (rva < candidate.virtualAddress + (candidate.virtualSize || candidate.sizeOfRawData)) {
      if (section) return null;
      section = candidate;
    }
  }
  if (!section) return null;
  const delta = rva - section.virtualAddress;
  const offset = section.pointerToRawData + delta;
  if (core.rvaToOff(rva) !== offset) return null;
  return { offset, characteristics: section.characteristics,
    size: Math.max(0, Math.min(next - rva, section.sizeOfRawData - delta, reader.size - offset,
      (section.virtualSize || section.sizeOfRawData) - delta, core.opt.SizeOfImage - rva)) };
};

export const createEhImage = (reader: FileRangeReader, core: PeWindowsCore): EhImage => {
  const available = (rva: number): number => mappedEhRange(reader, core, rva)?.size ?? 0;
  const read = async (rva: number, size: number): Promise<DataView | null> => {
    if (!isRvaRange(rva, size)) return null;
    const range = mappedEhRange(reader, core, rva);
    if (!range || range.size < size) return null;
    // PE MEM_READ is required even when data happens to reside in an executable section.
    // https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#section-flags
    if (!(range.characteristics & COFF_SECTION_CHARACTERISTICS.MEM_READ)) return null;
    const view = await reader.read(range.offset, size);
    return view.byteLength === size ? view : null;
  };
  const code = (rva: number, size = 1): boolean => {
    // AArch64 instructions and code pointers are 4-byte aligned (AAPCS64).
    // https://github.com/ARM-software/abi-aa/blob/main/aapcs64/aapcs64.rst
    if (core.coff.Machine === IMAGE_FILE_MACHINE_ARM64 && rva % 4) return false;
    if (!isRvaRange(rva, size)) return false;
    const range = mappedEhRange(reader, core, rva);
    if (!range || range.size < size) return false;
    // PE IMAGE_SCN_MEM_EXECUTE.
    return (range.characteristics & COFF_SECTION_CHARACTERISTICS.MEM_EXECUTE) !== 0;
  };
  return { available, read, code, reader, core, typeValidity: new Map(), functionInfos: new Map(),
    fh4UnwindMaps: new Map(), fh4SeparatedMaps: new Map() };
};
