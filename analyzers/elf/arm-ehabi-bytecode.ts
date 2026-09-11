export class ArmEhabiBytecode {
  position = 0;
  readonly issues: string[] = [];
  constructor(readonly bytes: number[]) {}
  byte(): number | null {
    if (this.position >= this.bytes.length) {
      this.issues.push("EHABI instruction is truncated.");
      return null;
    }
    return this.bytes[this.position++]!;
  }
  uleb(): bigint | null {
    let value = 0n;
    for (let index = 0; index < 5; index += 1) {
      const byte = this.byte();
      if (byte == null) return null;
      value |= BigInt(byte & 127) << BigInt(index * 7);
      if (byte < 128) return value;
    }
    this.issues.push("EHABI stack adjustment ULEB128 exceeds five bytes.");
    return null;
  }
}

export const ehabiRegisterMask = (prefix: string, start: number, mask: number): string =>
  Array.from({ length: 16 }, (_, index) => index).filter(index => mask & (1 << index))
    .map(index => `${prefix}${start + index}`).join(", ");

export const ehabiRegisterRange = (prefix: string, start: number, count: number): string =>
  Array.from({ length: count }, (_, index) => `${prefix}${start + index}`).join(", ");
