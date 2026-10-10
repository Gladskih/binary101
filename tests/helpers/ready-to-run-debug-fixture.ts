export const nibbleIntegers = (values: number[]): Uint8Array => {
  const nibbles = values.flatMap(value => {
    const digits = [value & 7];
    for (let rest = Math.floor(value / 8); rest; rest = Math.floor(rest / 8)) {
      digits.unshift((rest & 7) | 8);
    }
    return digits;
  });
  return Uint8Array.from({ length: Math.ceil(nibbles.length / 2) }, (_, index) =>
    nibbles[index * 2]! | ((nibbles[index * 2 + 1] ?? 0) << 4));
};

// Packed bounds fields follow the runtime's least-significant-bit-first writer.
// https://github.com/dotnet/runtime/blob/v10.0.0/src/coreclr/vm/debuginfostore.cpp
export const packedDebugBounds = (values: bigint[], nativeBits: number,
  ilBits: number): Uint8Array => {
  const width = nativeBits + ilBits + 2;
  const bytes = new Uint8Array(Math.ceil(values.length * width / 8));
  values.forEach((value, index) => {
    for (let bit = 0; bit < width; bit++) {
      bytes[(index * width + bit) >>> 3]! |= Number((value >> BigInt(bit)) & 1n) <<
        ((index * width + bit) & 7);
    }
  });
  return Uint8Array.from([...nibbleIntegers([values.length, nativeBits - 1, ilBits - 1]), ...bytes]);
};

export interface DebugBoundFixture {
  nativeDelta: number;
  ilOffset: number;
  source: number;
}

// RTR v16 packs source flags in bits 0-1, native delta next, and IL+3 last.
// https://github.com/dotnet/runtime/blob/v10.0.0/src/coreclr/vm/debuginfostore.cpp
export const packedBounds = (bounds: DebugBoundFixture[], nativeBits: number,
  ilBits: number): Uint8Array => packedDebugBounds(bounds.map(bound =>
  BigInt((bound.source & 16) ? 1 : 0) | BigInt(bound.source & 2) |
    (BigInt(bound.nativeDelta) << 2n) |
    (BigInt(bound.ilOffset + 3) << BigInt(nativeBits + 2))), nativeBits, ilBits);

export interface DebugVariableFixture {
  start: number;
  length: number;
  variableNumber: number;
  location: number;
  operands?: number[];
}

// cordebuginfo.h assigns the location tags; variable numbers are stored with a +4 bias.
// https://github.com/dotnet/runtime/blob/v10.0.0/src/coreclr/inc/cordebuginfo.h
export const debugVariables = (records: DebugVariableFixture[]): Uint8Array =>
  nibbleIntegers([records.length, ...records.flatMap(record => [record.start, record.length,
    record.variableNumber + 4, record.location, ...(record.operands ?? [])])]);

export const debugSection = (bounds: Uint8Array, variables: Uint8Array): Uint8Array =>
  // NativeArray count=1, one-byte index=1, leaf index=0, inline lookback=0; then two lengths.
  // https://github.com/dotnet/runtime/blob/v10.0.0/src/coreclr/tools/aot/ILCompiler.Reflection.ReadyToRun/DebugInfo.cs
  Uint8Array.from([8, 1, 0, 0, ...nibbleIntegers([bounds.length, variables.length]),
    ...bounds, ...variables]);
