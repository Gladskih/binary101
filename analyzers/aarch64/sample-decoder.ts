import type { DecodeResult, DecodedInstruction, Disassembler } from "llvm-aarch64-disasm";

export type Aarch64InstructionSample = { status: "invalid"; address: bigint } |
  Pick<DecodedInstruction, "status" | "address" | "length" | "features" | "controlFlow" | "target">;

// The fixed A64 decoder's feature gates depend on the word, not its PC. Only the branch
// target needs relocating; formatted operands/text are deliberately absent from this sample API.
// https://github.com/Gladskih/llvm-aarch64-disasm/blob/main/src/index.ts
export const createAarch64SampleDecoder = (decoder: Disassembler) => {
  const cache = new Map<number, DecodeResult>();
  return (bytes: Uint8Array, address: bigint): Aarch64InstructionSample => {
    const word = bytes.length < 4 ? undefined : new DataView(
      bytes.buffer, bytes.byteOffset, 4).getUint32(0, true);
    let instruction = word === undefined ? undefined : cache.get(word);
    if (!instruction) {
      instruction = decoder.decode(bytes.subarray(0, 4), { address: 0n })[0];
      if (!instruction) throw new Error("AArch64 decoder returned no instruction.");
      // Keep at most 4096 decoded words; repeated words avoid WASM/JSON/operand allocation.
      if (cache.size >= 4096) cache.clear();
      if (word !== undefined) cache.set(word, instruction);
    }
    if (instruction.status === "invalid") return { status: "invalid", address };
    return { status: instruction.status, address, length: instruction.length,
      features: instruction.features, controlFlow: instruction.controlFlow,
      ...(instruction.target === undefined ? {} : {
        target: BigInt.asUintN(64, address + instruction.target)
      }) };
  };
};
