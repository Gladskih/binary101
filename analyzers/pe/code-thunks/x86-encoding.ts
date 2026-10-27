// Intel SDM vol.2 JMP: FF /4 with ModRM 00 100 101 is a six-byte memory-indirect
// jump (absolute disp32 in x86, RIP+disp32 in x64). The DWORD immediate is relocated by LLD.
// https://github.com/llvm/llvm-project/blob/main/lld/COFF/Chunks.h#L500
// https://github.com/llvm/llvm-project/blob/main/lld/COFF/Chunks.cpp#L800
export const X86_INDIRECT_JUMP = { opcode: 0x25ff, length: 6, displacement: 2 } as const;

// JMP rel32 has a one-byte opcode followed by a signed DWORD displacement.
// Intel SDM vol.2 JMP; LLVM names this instruction JMP_4 and encodes opcode 0xE9.
// https://github.com/llvm/llvm-project/blob/main/llvm/lib/Target/X86/X86InstrControl.td
export const X86_RELATIVE_JUMP = { opcode: 0xe9, length: 5, displacement: 1 } as const;
