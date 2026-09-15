import type { DecodedInstruction, Disassembler } from "llvm-aarch64-disasm";

type CachedInstruction = { status: "invalid" } |
  Pick<DecodedInstruction, "status" | "length" | "features" | "controlFlow" | "target">;

export type Aarch64InstructionSample = CachedInstruction & { address: bigint };

const decodeSample = (decoder: Disassembler, bytes: Uint8Array): CachedInstruction => {
  const instruction = decoder.decode(bytes.subarray(0, 4), { address: 0n })[0];
  if (!instruction) throw new Error("AArch64 decoder returned no instruction.");
  if (instruction.status === "invalid") return { status: "invalid" };
  return { status: instruction.status, length: instruction.length,
    features: instruction.features, controlFlow: instruction.controlFlow,
    ...(instruction.target === undefined ? {} : { target: instruction.target }) };
};

// The fixed A64 decoder's feature gates depend on the word, not its PC. Only the branch
// target needs relocating; formatted operands/text are deliberately absent from this sample API.
// https://github.com/Gladskih/llvm-aarch64-disasm/blob/main/src/index.ts
export const createAarch64SampleDecoder = (decoder: Disassembler) => {
  // LM Studio ARM64, first 1M words: 242k misses versus 392k with the old 4096-word
  // flushing cache. Keep only ISA/flow metadata; replace collisions without flushing hot words.
  const words = new Uint32Array(65536);
  const samples = new Array<CachedInstruction | undefined>(65536);
  return (bytes: Uint8Array, address: bigint): Aarch64InstructionSample => {
    if (bytes.length < 4) return { ...decodeSample(decoder, bytes), address };
    const word = new DataView(bytes.buffer, bytes.byteOffset, 4).getUint32(0, true);
    // Multiplicative hashing spreads instruction bits across the fixed 16-bit slot index.
    const slot = Math.imul(word, 0x9e3779b1) >>> 16;
    let instruction = words[slot] === word ? samples[slot] : undefined;
    if (!instruction) {
      instruction = decodeSample(decoder, bytes);
      words[slot] = word;
      samples[slot] = instruction;
    }
    if (instruction.status === "invalid") return { status: "invalid", address };
    return { ...instruction, address,
      ...(instruction.target === undefined ? {} : {
        target: BigInt.asUintN(64, address + instruction.target)
      }) };
  };
};
