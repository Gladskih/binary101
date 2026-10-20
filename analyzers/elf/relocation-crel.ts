import type { ElfRelocationStream } from "./relocation-stream.js";
import type { ElfRelocation, ElfRelocationImage } from "./relocation-types.js";

// Experimental LLVM CREL: count<<3 | explicit-addends<<2 | offset-shift.
// Each record has 2/3 flag bits followed by ULEB offset delta and SLEB deltas.
// Integer accumulators wrap at their ABI widths, as in upstream decodeCrel.
// https://github.com/llvm/llvm-project/blob/llvmorg-23.1.3/llvm/include/llvm/Object/ELF.h
interface CrelState { offset: bigint; symbol: bigint; type: bigint; addend: bigint }

const advanceState = async (stream: ElfRelocationStream, state: CrelState,
  flagBits: number, bits: number): Promise<void> => {
  const first = await stream.byte();
  const delta = BigInt((first & 0x7f) >> flagBits) +
    (first & 0x80 ? (await stream.unsigned()) << BigInt(7 - flagBits) : 0n);
  state.offset = BigInt.asUintN(bits, state.offset + delta);
  if (first & 1) state.symbol = BigInt.asUintN(32, state.symbol + await stream.signed());
  if (first & 2) state.type = BigInt.asUintN(32, state.type + await stream.signed());
  if (first & 4 && flagBits === 3) state.addend = BigInt.asIntN(bits, state.addend + await stream.signed());
};

export async function* readElfCrelRelocations(
  stream: ElfRelocationStream, elf: ElfRelocationImage, tableIndex: number
): AsyncGenerator<ElfRelocation> {
  const header = await stream.unsigned();
  const count = header >> 3n;
  const flagBits = header & 4n ? 3 : 2;
  const shift = header & 3n;
  const bits = elf.is64 ? 64 : 32;
  const state: CrelState = { offset: 0n, symbol: 0n, type: 0n, addend: 0n };
  // Every CREL record consumes at least one byte, including fully repeated records.
  if (count > BigInt(stream.end - stream.position)) throw new Error("truncated CREL relocation count");
  for (let index = 0n; index < count; index++) {
    const recordOffset = stream.position;
    await advanceState(stream, state, flagBits, bits);
    yield { tableIndex, recordOffset, offset: BigInt.asUintN(bits, state.offset << shift),
      symbolIndex: Number(state.symbol), type: Number(state.type), addend: flagBits === 3 ? state.addend : null,
      symbol: null, target: null };
  }
}
