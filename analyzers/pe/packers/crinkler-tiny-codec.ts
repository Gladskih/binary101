// Crinkler Compress1k and header22_1k.asm describe the same contexts and bit stream.
// https://github.com/runestubbe/Crinkler/blob/f74d964/source/Compressor/Compressor.cpp
// https://github.com/runestubbe/Crinkler/blob/f74d964/source/Crinkler/modules/header22_1k.asm
const BITS_PER_BYTE = 8;
const BYTE_RADIX = 2 ** BITS_PER_BYTE;
const WORD_BITS = Uint32Array.BYTES_PER_ELEMENT * BITS_PER_BYTE;
// AritCodeInit sets the top bit of a 32-bit interval. AritDecodeLoop refills up to
// that bit, which bounds the zero-filled lookahead available in a mapped image.
const ARITHMETIC_LOOKAHEAD_BITS = WORD_BITS - 1;
const NORMALIZED_INTERVAL = 2 ** ARITHMETIC_LOOKAHEAD_BITS;

export interface CrinklerTinyModel {
  baseOne: number;
  baseZero: number;
  mask: number;
  boost: number;
}

interface ContextCount {
  zeros: number;
  ones: number;
}

interface ContextModel {
  distances: number[];
  prefixes: Map<number | bigint, ContextCount>[];
}

const makeContextModels = (mask: number): ContextModel[] =>
  // The 32 mask bits are followed by model 32, which is always enabled.
  Array.from({ length: WORD_BITS + 1 }, (_, index) => index)
    .filter(index => index === WORD_BITS || ((mask >>> index) & 1) !== 0)
    .map(index => ({
      // Model index zero represents the all-eight-bytes context (unsigned -1).
      distances: Array.from({ length: 8 }, (_, bit) => bit + 1)
        .filter(distance => ((index - 1) & (1 << (distance - 1))) !== 0),
      // Counts are updated incrementally, including the zero context before the first byte.
      prefixes: Array.from({ length: BITS_PER_BYTE },
        () => new Map([[0, { zeros: 1, ones: 0 }]]))
    }));

const contextKey = (
  data: Uint8Array, offset: number, prefix: number, distances: readonly number[]
): number | bigint => {
  // A prefix and up to five history bytes fit exactly in a JS number.
  if (distances.length > 5) {
    let key = BigInt(prefix);
    for (const distance of distances) key = (key << 8n) | BigInt(data[offset - distance] ?? 0);
    return key;
  }
  let key = prefix;
  for (const distance of distances) key = key * BYTE_RADIX + (data[offset - distance] ?? 0);
  return key;
};

const contextCounts = (
  models: ContextModel[], data: Uint8Array, offset: number, bit: number, prefix: number
): ContextCount[] => models.map(({ distances, prefixes }) => {
  const contexts = prefixes[bit]!;
  const wideKey = contextKey(data, offset, prefix, distances);
  const key = wideKey === 0n ? 0 : wideKey;
  const previous = contexts.get(key);
  if (previous) return previous;
  const initial = { zeros: 0, ones: 0 };
  contexts.set(key, initial);
  return initial;
});

const probability = (counts: ContextCount[], model: CrinklerTinyModel): [number, number] => {
  let one = model.baseOne;
  let zero = model.baseZero;
  for (const { zeros, ones } of counts) {
    const weight = zeros === 0 || ones === 0 ? model.boost : 1;
    one += ones * weight;
    zero += zeros * weight;
  }
  return [one, zero];
};

const updateCounts = (counts: ContextCount[], value: number): void => {
  for (const count of counts) {
    count.zeros = value ? (count.zeros + 1) >>> 1 : count.zeros + 1;
    count.ones = value ? count.ones + 1 : (count.ones + 1) >>> 1;
  }
};

class ArithmeticDecoder {
  private interval = 1;
  private value = 0;
  private bit = 0;
  private readonly verifier: ArithmeticVerifier;

  constructor(private readonly bytes: Uint8Array) {
    this.verifier = new ArithmeticVerifier(bytes.length);
  }

  read(one: number, zero: number): number | null {
    while (this.interval < NORMALIZED_INTERVAL) {
      if (this.bit >= this.bytes.length * BITS_PER_BYTE + ARITHMETIC_LOOKAHEAD_BITS) return null;
      const byte = this.bytes[Math.floor(this.bit / BITS_PER_BYTE)] ?? 0;
      const next = (byte >>> (this.bit % BITS_PER_BYTE)) & 1;
      this.value = this.value * 2 + next;
      this.interval *= 2;
      this.bit += 1;
    }
    const threshold = Number(BigInt(this.interval) * BigInt(one) / BigInt(one + zero));
    if (threshold <= 0 || threshold >= this.interval) return null;
    const value = this.value < threshold ? 1 : 0;
    if (!value) this.value -= threshold;
    this.interval = value ? threshold : this.interval - threshold;
    this.verifier.update(value, threshold, this.interval);
    return value;
  }

  verifiedPackedSize(): number | null {
    let range = this.interval;
    while (range < NORMALIZED_INTERVAL) range *= 2;
    return this.verifier.verify(this.bytes, range);
  }
}

// AritCode.cpp specifies canonical termination. Replay the encoder as bits are decoded so
// the result has an exact file span, including when unrelated bytes follow the stream.
// https://github.com/runestubbe/Crinkler/blob/f74d964/source/Compressor/AritCode.cpp
class ArithmeticVerifier {
  private minimum = 0;
  private bit = -1;
  private readonly encoded: Uint8Array;

  constructor(length: number) {
    this.encoded = new Uint8Array(length);
  }

  private carry(): void {
    for (let bit = this.bit - 1; bit >= 0; bit -= 1) {
      const byte = Math.floor(bit / BITS_PER_BYTE);
      const mask = 1 << (bit % BITS_PER_BYTE);
      const prior = this.encoded[byte] ?? 0;
      this.encoded[byte] = prior ^ mask;
      if ((prior & mask) === 0) break;
    }
  }

  update(value: number, threshold: number, interval: number): void {
    if (!value) {
      const prior = this.minimum;
      this.minimum = (prior + threshold) >>> 0;
      if (this.minimum < prior) this.carry();
    }
    for (let range = interval; range < NORMALIZED_INTERVAL; range *= 2) {
      this.bit += 1;
      if (this.minimum >= NORMALIZED_INTERVAL) this.carry();
      this.minimum = (this.minimum << 1) >>> 0;
    }
  }

  verify(bytes: Uint8Array, interval: number): number | null {
    if (this.minimum) {
      if (this.minimum + interval <= NORMALIZED_INTERVAL * 2) this.bit += 1;
      this.carry();
    }
    const size = Math.ceil(this.bit / BITS_PER_BYTE);
    if (size < 0 || size > bytes.length) return null;
    return this.encoded.subarray(0, size).every((byte, index) => byte === bytes[index])
      ? size : null;
  }
}

// Local analysis budget, not a format limit. Tiny Header is intended for ~1 KiB intros.
// Four times that size bounds the 33 models × 8 bit positions × output length cache.
// https://github.com/runestubbe/Crinkler/blob/f74d964/doc/manual.txt#tinyheader
export const CRINKLER_TINY_OUTPUT_LIMIT = 4096;

// Base weights are loaded by push imm8 and must be positive after sign extension.
const validProbability = (value: number): boolean =>
  Number.isInteger(value) && value > 0 && value < BYTE_RADIX / 2;

const validModel = ({ baseOne, baseZero, boost }: CrinklerTinyModel): boolean =>
  validProbability(baseOne) && validProbability(baseZero) &&
  Number.isInteger(boost) && boost > 0 && boost < BYTE_RADIX;

const decodeByte = (
  decoder: ArithmeticDecoder, model: CrinklerTinyModel, contexts: ContextModel[],
  data: Uint8Array, offset: number
): number | null => {
  let prefix = 0;
  for (let bit = 0; bit < BITS_PER_BYTE; bit += 1) {
    const counts = contextCounts(contexts, data, offset, bit, prefix);
    const value = decoder.read(...probability(counts, model));
    if (value == null) return null;
    prefix = prefix * 2 + value;
    updateCounts(counts, value);
  }
  return prefix;
};

export const decodeCrinklerTiny = (
  bytes: Uint8Array, size: number, model: CrinklerTinyModel
): { data: Uint8Array; packedSize: number } | null => {
  if (!bytes.length || !Number.isInteger(size) || size < 1 ||
      size > CRINKLER_TINY_OUTPUT_LIMIT) return null;
  if (!validModel(model)) return null;
  const data = new Uint8Array(size);
  const contexts = makeContextModels(model.mask);
  const decoder = new ArithmeticDecoder(bytes);
  for (let index = 0; index < size; index += 1) {
    const next = decodeByte(decoder, model, contexts, data, index);
    if (next == null) return null;
    data[index] = next;
  }
  const packedSize = decoder.verifiedPackedSize();
  return packedSize == null ? null : { data, packedSize };
};
