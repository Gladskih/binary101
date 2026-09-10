import { ElfCoreNoteReader } from "./core-note-reader.js";
import type { ElfCoreNote } from "./core-note-types.js";
import { parseElfCoreProcess, parseElfCoreStatus } from "./core-process.js";
import { parseElfCoreAuxv, parseElfCoreMappings } from "./core-mappings.js";
import { parseElfCoreFloatingPoint, parseElfCoreXstate } from "./core-floating-point.js";

// NT_*: https://raw.githubusercontent.com/torvalds/linux/master/include/uapi/linux/elf.h
export const elfCoreNoteNames: Readonly<Record<number, string>> = {
  1: "NT_PRSTATUS", 2: "NT_FPREGSET", 3: "NT_PRPSINFO", 6: "NT_AUXV",
  0x202: "NT_X86_XSTATE", 0x53494749: "NT_SIGINFO", 0x46494c45: "NT_FILE"
};

export const parseElfCoreNote = (
  bytes: Uint8Array, type: number, wordSize: 4 | 8, byteOrder: "little" | "big", machine: number
): ElfCoreNote => {
  const reader = new ElfCoreNoteReader(bytes, wordSize, byteOrder);
  switch (type) {
    case 1: return parseElfCoreStatus(reader, machine);
    case 2: return parseElfCoreFloatingPoint(reader, machine);
    case 3: return parseElfCoreProcess(reader, machine);
    case 6: return parseElfCoreAuxv(reader);
    case 0x202: return parseElfCoreXstate(reader, machine);
    case 0x46494c45: return parseElfCoreMappings(reader);
    case 0x53494749: return { fields: ["Signal", "Errno", "Code"].flatMap((name, index) =>
      reader.contains(index * 4, 4) ? [{ name, value: reader.signed(index * 4, 4) }] : []),
    issues: reader.issues };
    default: return { fields: [], issues: [`Unsupported core note type 0x${type.toString(16)}.`] };
  }
};
