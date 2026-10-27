import { IMAGE_FILE_MACHINE_ARM64, IMAGE_FILE_MACHINE_ARMNT, IMAGE_FILE_MACHINE_AMD64,
  IMAGE_FILE_MACHINE_I386 } from "../../coff/machine.js";
import { X86_INDIRECT_JUMP, X86_RELATIVE_JUMP } from "../code-thunks/x86-encoding.js";
import { readThumbMovePair } from "../code-thunks/thumb-move.js";
import type { EhImage } from "./types.js";

type EhThunk = { kind: "import" | "branch"; rva: number };

const preferredRva = (image: EhImage, value: number): number =>
  Number(BigInt(value) - image.core.opt.ImageBase);

const arm64Thunk = (view: DataView, rva: number): EhThunk | null => {
  const first = view.getUint32(0, true);
  if ((first & 0xfc000000) >>> 0 === 0x14000000) {
    return { kind: "branch", rva: rva + (first << 6 >> 4) };
  }
  const second = view.getUint32(4, true);
  // Only LLD's exact x16 import thunk; arbitrary AArch64 code is not interpreted.
  if (((first & 0x9f00001f) >>> 0) !== 0x90000010 ||
      ((second & 0xffc003ff) >>> 0) !== 0xf9400210 ||
      view.getUint32(8, true) !== 0xd61f0200) return null;
  const immediate = ((first >>> 29) & 3) | ((first >>> 5) & 0x7ffff) * 4;
  const signed = immediate >= 0x100000 ? immediate - 0x200000 : immediate;
  return { kind: "import", rva: Math.floor(rva / 4096) * 4096 + signed * 4096 +
    ((second >>> 10) & 0xfff) * 8 };
};

const thumbThunk = (image: EhImage, view: DataView): EhThunk | null => {
  const immediate = readThumbMovePair(view, 0, 12);
  if (immediate == null || view.getUint32(8, true) !== 0xf000f8dc) return null;
  return { kind: "import", rva: preferredRva(image, immediate) };
};

const x86Thunk = (image: EhImage, view: DataView, rva: number): EhThunk | null => {
  // JMP rel32 and JMP [absolute/RIP-relative disp32], Intel SDM vol.2 JMP.
  // The exact import sequences are emitted by LLD COFF/Chunks.h (linked below).
  if (view.getUint8(0) === X86_RELATIVE_JUMP.opcode) return { kind: "branch",
    rva: rva + X86_RELATIVE_JUMP.length + view.getInt32(X86_RELATIVE_JUMP.displacement, true) };
  if (view.getUint16(0, true) !== X86_INDIRECT_JUMP.opcode) return null;
  return { kind: "import", rva: image.core.coff.Machine === IMAGE_FILE_MACHINE_I386
    ? preferredRva(image, view.getUint32(X86_INDIRECT_JUMP.displacement, true))
    : rva + X86_INDIRECT_JUMP.length + view.getInt32(X86_INDIRECT_JUMP.displacement, true) };
};

const thunkSize = (machine: number): number =>
  machine === IMAGE_FILE_MACHINE_ARM64 || machine === IMAGE_FILE_MACHINE_ARMNT ? 12 : 6;

export const decodeEhThunk = async (image: EhImage, rva: number): Promise<EhThunk | null> => {
  // LLD's import thunks and relocations are specified together here:
  // https://github.com/llvm/llvm-project/blob/main/lld/COFF/Chunks.h
  // https://github.com/llvm/llvm-project/blob/main/lld/COFF/Chunks.cpp
  const machine = image.core.coff.Machine;
  const size = thunkSize(machine);
  if (!image.code(rva, size)) return null;
  const view = await image.read(rva, size);
  if (!view) return null;
  if (machine === IMAGE_FILE_MACHINE_ARM64) return arm64Thunk(view, rva);
  if (machine === IMAGE_FILE_MACHINE_ARMNT) return rva % 2 ? null : thumbThunk(image, view);
  if (machine !== IMAGE_FILE_MACHINE_AMD64 && machine !== IMAGE_FILE_MACHINE_I386) return null;
  return x86Thunk(image, view, rva);
};
