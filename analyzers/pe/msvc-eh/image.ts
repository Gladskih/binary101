import { COFF_SECTION_CHARACTERISTICS } from "../../coff/layout.js";
import { IMAGE_FILE_MACHINE_ARM64 } from "../../coff/machine.js";
import type { FileRangeReader } from "../../file-range-reader.js";
import type { PeWindowsCore } from "../types.js";
import type { EhImage } from "./types.js";
import { isRvaRange } from "../rva-mapping.js";

export const createEhImage = (reader: FileRangeReader, core: PeWindowsCore): EhImage => {
  const sectionAt = (rva: number) => {
    // Reject ambiguous virtual mappings rather than trusting section precedence.
    const matches = core.sections.filter(section => rva >= section.virtualAddress &&
      rva < section.virtualAddress + (section.virtualSize || section.sizeOfRawData));
    return matches.length === 1 ? matches[0] : undefined;
  };
  const available = (rva: number): number => {
    if (!isRvaRange(rva, 1) || rva >= core.opt.SizeOfImage) return 0;
    const section = sectionAt(rva);
    if (!section) return 0;
    const delta = rva - section.virtualAddress;
    const offset = section.pointerToRawData + delta;
    if (core.rvaToOff(rva) !== offset) return 0;
    const next = core.sections.filter(other => other.virtualAddress > rva)
      .reduce((end, other) => Math.min(end, other.virtualAddress), core.opt.SizeOfImage);
    return Math.max(0, Math.min(next - rva, section.sizeOfRawData - delta, reader.size - offset,
      (section.virtualSize || section.sizeOfRawData) - delta, core.opt.SizeOfImage - rva));
  };
  const read = async (rva: number, size: number): Promise<DataView | null> => {
    if (!isRvaRange(rva, size) || available(rva) < size) return null;
    const section = sectionAt(rva)!;
    // PE MEM_READ is required even when data happens to reside in an executable section.
    // https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#section-flags
    if (!(section.characteristics & COFF_SECTION_CHARACTERISTICS.MEM_READ)) return null;
    const view = await reader.read(section.pointerToRawData + rva - section.virtualAddress, size);
    return view.byteLength === size ? view : null;
  };
  const code = (rva: number, size = 1): boolean => {
    // AArch64 instructions and code pointers are 4-byte aligned (AAPCS64).
    // https://github.com/ARM-software/abi-aa/blob/main/aapcs64/aapcs64.rst
    if (core.coff.Machine === IMAGE_FILE_MACHINE_ARM64 && rva % 4) return false;
    if (!isRvaRange(rva, size) || available(rva) < size) return false;
    // PE IMAGE_SCN_MEM_EXECUTE.
    return (sectionAt(rva)!.characteristics & COFF_SECTION_CHARACTERISTICS.MEM_EXECUTE) !== 0;
  };
  return { available, read, code, reader, core, typeValidity: new Map(), functionInfos: new Map(),
    fh4UnwindMaps: new Map(), fh4SeparatedMaps: new Map() };
};
