import { ElfCoreNoteReader } from "./core-note-reader.js";
import type { ElfCoreNote } from "./core-note-types.js";
import { parseElfCoreProcess, parseElfCoreStatus } from "./core-process.js";
import { parseElfCoreAuxv, parseElfCoreMappings } from "./core-mappings.js";
import { parseElfCoreFloatingPoint, parseElfCoreXstate } from "./core-floating-point.js";

const parseCoreSignal = (reader: ElfCoreNoteReader): ElfCoreNote => ({
  fields: ["Signal", "Errno", "Code"].flatMap((name, index) =>
    reader.contains(index * 4, 4) ? [{ name, value: reader.signed(index * 4, 4) }] : []),
  issues: reader.issues
});

// NT_*: https://raw.githubusercontent.com/torvalds/linux/master/include/uapi/linux/elf.h
const coreNoteRegistry: Readonly<Record<number, {
  name: string;
  decode: (reader: ElfCoreNoteReader, machine: number) => ElfCoreNote;
}>> = {
  1: { name: "NT_PRSTATUS", decode: parseElfCoreStatus },
  2: { name: "NT_FPREGSET", decode: parseElfCoreFloatingPoint },
  3: { name: "NT_PRPSINFO", decode: parseElfCoreProcess },
  6: { name: "NT_AUXV", decode: parseElfCoreAuxv },
  0x202: { name: "NT_X86_XSTATE", decode: parseElfCoreXstate },
  0x53494749: { name: "NT_SIGINFO", decode: parseCoreSignal },
  0x46494c45: { name: "NT_FILE", decode: parseElfCoreMappings }
};

export const elfCoreNoteName = (type: number): string | null => coreNoteRegistry[type]?.name ?? null;

export const parseElfCoreNote = (
  bytes: Uint8Array, type: number, wordSize: 4 | 8, byteOrder: "little" | "big", machine: number
): ElfCoreNote => {
  const descriptor = coreNoteRegistry[type];
  return descriptor ? descriptor.decode(new ElfCoreNoteReader(bytes, wordSize, byteOrder), machine)
    : { fields: [], issues: [`Unsupported core note type 0x${type.toString(16)}.`] };
};
