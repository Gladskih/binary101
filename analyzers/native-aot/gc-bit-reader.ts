// GCInfo's bit stream has low-bit-first fields and little-endian variable groups.
// Signed groups use sign extension, unlike NativeFormat signed-magnitude integers.
// https://github.com/dotnet/runtime/blob/v10.0.0/src/coreclr/inc/gcinfodecoder.h
export class GcBitReader {
  constructor(readonly bytes: Uint8Array, public position = 0) {}

  at(position: number): GcBitReader { return new GcBitReader(this.bytes, position); }

  bits(width: number): number {
    if (!Number.isSafeInteger(width) || width < 0) throw new Error("Invalid GC field width.");
    if (!Number.isSafeInteger(this.position) || this.position < 0) throw new Error("Invalid GC bit position.");
    if (width > this.bytes.length * 8 - this.position) throw new Error("GC info is truncated.");
    let value = 0;
    for (let collected = 0; collected < width;) {
      const bit = this.position % 8;
      const take = Math.min(width - collected, 8 - bit);
      const chunk = (this.bytes[Math.floor(this.position / 8)]! >>> bit) & (2 ** take - 1);
      // A wide pointer may have zero high bits. Avoid 0 * Infinity for those fields.
      if (chunk) value += chunk * 2 ** collected;
      collected += take;
      this.position += take;
    }
    if (!Number.isSafeInteger(value)) throw new Error("GC field exceeds exact numeric precision.");
    return value;
  }

  #groups(base: number): { value: bigint; width: number } {
    if (!Number.isInteger(base) || base < 1 || base > 31) throw new Error("Invalid GC encoding base.");
    let value = 0n;
    // Runtime BitStreamReader shifts in x64 size_t and requires each complete group
    // to fit that 64-bit word. UInt32/Int32 validation applies after decoding.
    for (let shift = 0; shift + base <= 64; shift += base) {
      const chunk = this.bits(base + 1);
      value |= BigInt(chunk % 2 ** base) << BigInt(shift);
      if (chunk < 2 ** base) return { value, width: shift + base };
    }
    throw new Error("GC integer encoding exceeds the x64 native-word width.");
  }

  unsigned(base: number): number {
    const { value } = this.#groups(base);
    if (value > 0xffffffffn) throw new Error("GC integer exceeds UInt32.");
    return Number(value);
  }

  signed(base: number): number {
    const decoded = this.#groups(base);
    const value = BigInt.asIntN(decoded.width, decoded.value);
    if (value < -2147483648n || value > 2147483647n) throw new Error("GC integer exceeds Int32.");
    return Number(value);
  }
}
