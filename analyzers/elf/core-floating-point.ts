import type { ElfCoreNote } from "./core-note-types.js";
import type { ElfCoreNoteReader } from "./core-note-reader.js";

// https://raw.githubusercontent.com/torvalds/linux/master/arch/x86/include/asm/user_64.h
// https://raw.githubusercontent.com/torvalds/linux/master/arch/arm64/include/uapi/asm/ptrace.h
export const parseElfCoreFloatingPoint = (reader: ElfCoreNoteReader, machine: number): ElfCoreNote => {
  const result: ElfCoreNote = { fields: [], issues: reader.issues };
  if (reader.wordSize !== 8 || ![62, 183].includes(machine)) {
    reader.issues.push(`Unsupported floating point core ABI: machine ${machine}.`);
    return result;
  }
  if (!reader.contains(0, machine === 62 ? 512 : 528)) return result;
  if (machine === 183) {
    result.registers = reader.fields(Array.from({ length: 32 }, (_, index) => `v${index}`), 0, 16);
    result.fields = reader.fields(["FPSR", "FPCR"], 512, 4);
    return result;
  }
  result.fields = [...reader.fields(["FCW", "FSW", "FTW", "FOP"], 0, 2),
    ...reader.fields(["Instruction pointer", "Data pointer"], 8, 8),
    ...reader.fields(["MXCSR", "MXCSR mask"], 24, 4)];
  result.registers = [...Array.from({ length: 8 }, (_, index) => ({ name: `st${index}`,
    value: reader.unsigned(32 + index * 16, 10) })),
  ...reader.fields(Array.from({ length: 16 }, (_, index) => `xmm${index}`), 160, 16)];
  return result;
};

// XSAVE header: Linux arch/x86/include/asm/fpu/types.h. Component locations beyond
// the legacy region depend on CPUID or compacted layout; do not infer those from size.
export const parseElfCoreXstate = (reader: ElfCoreNoteReader, machine: number): ElfCoreNote => {
  const result = parseElfCoreFloatingPoint(reader, machine);
  if (machine !== 62 || reader.wordSize !== 8) return result;
  result.fields.push(...reader.fields(["XSTATE_BV", "XCOMP_BV"], 512, 8));
  if (reader.contains(512, 64)) {
    reader.issues.push("XSAVE extended component payloads require their architecture layout and are not decoded.");
  }
  return result;
};
