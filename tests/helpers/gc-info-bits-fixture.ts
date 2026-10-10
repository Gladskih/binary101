export class GcInfoBitsFixture {
  readonly bits: number[] = [];

  field(value: number, width: number): this {
    for (let bit = 0; bit < width; bit++) this.bits.push(Math.floor(value / 2 ** bit) & 1);
    return this;
  }

  repeatedField(value: number, width: number, count: number): this {
    for (let index = 0; index < count; index++) this.field(value, width);
    return this;
  }

  unsigned(value: number, base: number): this {
    let rest = value;
    do {
      const chunk = rest % 2 ** base;
      rest = Math.floor(rest / 2 ** base);
      this.field(chunk + (rest ? 2 ** base : 0), base + 1);
    } while (rest);
    return this;
  }

  signed(value: number, base: number): this {
    let rest = BigInt(value);
    let more: boolean;
    do {
      const chunk = Number(BigInt.asUintN(base, rest));
      rest >>= BigInt(base);
      more = !(rest === 0n && chunk < 2 ** (base - 1) ||
        rest === -1n && chunk >= 2 ** (base - 1));
      this.field(chunk + (more ? 2 ** base : 0), base + 1);
    } while (more);
    return this;
  }

  bytes(): Uint8Array {
    const bytes = new Uint8Array(Math.ceil(this.bits.length / 8));
    this.bits.forEach((bit, index) => { bytes[Math.floor(index / 8)]! |= bit << (index & 7); });
    return bytes;
  }
}
