import type { ElfCoreField, ElfCoreNote } from "./core-note-types.js";
import type { ElfCoreNoteReader } from "./core-note-reader.js";

// Linux elf_prstatus/elf_prpsinfo and register sets:
// https://raw.githubusercontent.com/torvalds/linux/master/include/linux/elfcore.h
// https://raw.githubusercontent.com/torvalds/linux/master/arch/x86/include/asm/user_64.h
// https://raw.githubusercontent.com/torvalds/linux/master/arch/x86/include/asm/user_32.h
// https://raw.githubusercontent.com/torvalds/linux/master/arch/arm64/include/uapi/asm/ptrace.h
const registerNames: Record<string, string[]> = {
  "62:8": "r15 r14 r13 r12 rbp rbx r11 r10 r9 r8 rax rcx rdx rsi rdi orig_rax rip cs eflags rsp ss fs_base gs_base ds es fs gs".split(" "),
  "3:4": "ebx ecx edx esi edi ebp eax ds es fs gs orig_eax eip cs eflags esp ss".split(" "),
  "183:8": [...Array.from({ length: 31 }, (_, index) => `x${index}`), "sp", "pc", "pstate"]
};

export const parseElfCoreStatus = (reader: ElfCoreNoteReader, machine: number): ElfCoreNote => {
  const fields: ElfCoreField[] = [];
  const registers = registerNames[`${machine}:${reader.wordSize}`];
  if (!registers) {
    reader.issues.push(`Unsupported core register ABI: machine ${machine}, word size ${reader.wordSize}.`);
    return { fields, issues: reader.issues };
  }
  fields.push(...["Signal", "Code", "Errno"].flatMap((name, index) =>
    reader.contains(index * 4, 4) ? [{ name, value: reader.signed(index * 4, 4) }] : []));
  fields.push(...reader.fields(["Current signal"], 12, 2));
  fields.push(...reader.fields(["Pending signals", "Held signals"], 16, reader.wordSize));
  const pidOffset = 16 + 2 * reader.wordSize;
  fields.push(...reader.fields(["PID", "Parent PID", "Process group", "Session"], pidOffset, 4));
  const times = ["User", "System", "Child user", "Child system"];
  fields.push(...reader.fields(times.flatMap(name => [`${name} seconds`, `${name} microseconds`]),
    pidOffset + 16, reader.wordSize));
  const registerOffset = pidOffset + 16 + 8 * reader.wordSize;
  fields.push(...reader.fields(["FP valid"], registerOffset + registers.length * reader.wordSize, 4));
  return { fields, registers: reader.fields(registers, registerOffset, reader.wordSize),
    issues: reader.issues };
};

export const parseElfCoreProcess = (reader: ElfCoreNoteReader, machine: number): ElfCoreNote => {
  const fields: ElfCoreField[] = [];
  if (!registerNames[`${machine}:${reader.wordSize}`]) {
    reader.issues.push(`Unsupported core process ABI: machine ${machine}.`);
    return { fields, issues: reader.issues };
  }
  // i386 __kernel_uid_t/__kernel_gid_t are 16-bit, unlike the supported LP64 ABIs.
  // https://raw.githubusercontent.com/torvalds/linux/master/arch/x86/include/uapi/asm/posix_types_32.h
  const uidWidth = reader.wordSize === 4 ? 2 : 4;
  const pidOffset = reader.wordSize * 2 + uidWidth * 2;
  fields.push(...reader.fields(["State", "State character", "Zombie"], 0, 1));
  if (reader.contains(3, 1)) fields.push({ name: "Nice", value: reader.signed(3, 1) });
  fields.push(...reader.fields(["Flags"], reader.wordSize, reader.wordSize));
  fields.push(...reader.fields(["UID", "GID"], reader.wordSize * 2, uidWidth));
  fields.push(...reader.fields(["PID", "Parent PID", "Process group", "Session"], pidOffset, 4));
  if (reader.contains(pidOffset + 16, 96)) {
    fields.push({ name: "Executable", value: reader.text(pidOffset + 16, 16) },
      { name: "Arguments", value: reader.text(pidOffset + 32, 80) });
  }
  return { fields, issues: reader.issues };
};
