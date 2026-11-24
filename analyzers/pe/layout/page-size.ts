import { IMAGE_FILE_MACHINE_IA64 } from "../../coff/machine.js";

// The PE section data rules use 4 KiB pages for x86/MIPS and 8 KiB for Itanium.
// https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#section-data
export const getPeArchitecturePageSize = (machine: number): number =>
  machine === IMAGE_FILE_MACHINE_IA64 ? 0x2000 : 0x1000;
