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

export const debugSection = (bounds: Uint8Array, variables: Uint8Array): Uint8Array =>
  // NativeArray count=1, one-byte index=1, leaf index=0, lookback=0.
  Uint8Array.from([8, 1, 0, 0, ...nibbleIntegers([bounds.length, variables.length]),
    ...bounds, ...variables]);
