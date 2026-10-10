import { NibbleReader } from "../../native-aot/nibble-reader.js";
import type { ReadyToRunDebugBound } from "./ready-to-run-debug-types.js";

// The producer changed to packed fields in RTR v16; both formats bias IL offsets by -3.
// https://github.com/dotnet/runtime/blob/v10.0.0/src/coreclr/vm/debuginfostore.cpp
// https://github.com/dotnet/runtime/blob/v10.0.0/src/coreclr/tools/aot/ILCompiler.Reflection.ReadyToRun/DebugInfo.cs
function* nibbleBounds(reader: NibbleReader, count: number): Generator<ReadyToRunDebugBound> {
  let nativeOffset = 0;
  for (let index = 0; index < count; index++) {
    nativeOffset += reader.unsigned();
    if (nativeOffset > 0xffffffff) throw new Error("Debug native offset overflow.");
    yield { nativeOffset, ilOffset: reader.unsigned() - 3, source: reader.unsigned() };
  }
}

const packedValue = (bytes: Uint8Array, bitOffset: number, width: number): bigint => {
  if (bitOffset + width > bytes.length * 8) throw new Error("Packed debug bounds are truncated.");
  let value = 0n;
  const end = Math.ceil((bitOffset + width) / 8);
  for (let offset = Math.floor(bitOffset / 8); offset < end; offset++) {
    value |= BigInt(bytes[offset]!) << BigInt((offset - Math.floor(bitOffset / 8)) * 8);
  }
  return (value >> BigInt(bitOffset & 7)) & ((1n << BigInt(width)) - 1n);
};

function* packedBounds(reader: NibbleReader, count: number): Generator<ReadyToRunDebugBound> {
  const nativeBits = reader.unsigned() + 1;
  const ilBits = reader.unsigned() + 1;
  if (nativeBits > 32 || ilBits > 32) throw new Error("Debug bit width exceeds UInt32.");
  const width = nativeBits + ilBits + 2;
  const start = reader.byteOffset * 8;
  let nativeOffset = 0;
  for (let index = 0; index < count; index++) {
    const value = packedValue(reader.bytes, start + index * width, width);
    nativeOffset += Number((value >> 2n) & ((1n << BigInt(nativeBits)) - 1n));
    if (nativeOffset > 0xffffffff) throw new Error("Debug native offset overflow.");
    yield { nativeOffset, ilOffset: Number(value >> BigInt(nativeBits + 2)) - 3,
      source: (Number(value & 1n) * 16) | Number(value & 2n) };
  }
}

export const readDebugBounds = (bytes: Uint8Array, majorVersion: number,
  warnings: Set<string>): ReadyToRunDebugBound[] => {
  const bounds: ReadyToRunDebugBound[] = [];
  try {
    const reader = new NibbleReader(bytes);
    const count = reader.unsigned();
    for (const bound of majorVersion >= 16 ? packedBounds(reader, count) : nibbleBounds(reader, count)) {
      bounds.push(bound);
    }
  } catch (error) { warnings.add(`Debug bounds: ${(error as Error).message}`); }
  return bounds;
};
