"use strict";

// DS-01 bit codes and repeat lengths follow bmfdec's DMSDOS-derived decoder.
// https://github.com/pali/bmfdec/blob/master/bmfdec.c#L73-L225
interface Bits { bytes: Uint8Array; position: number }

const read = (bits: Bits, count: number): number | null => {
  if (bits.position + count > bits.bytes.length * 8) return null;
  let result = 0;
  for (let index = 0; index < count; index += 1) {
    const bit = bits.position + index;
    result |= (((bits.bytes[bit >> 3] ?? 0) >> (bit & 7)) & 1) << index;
  }
  bits.position += count;
  return result;
};

const peek = (bits: Bits): number => {
  let result = 0;
  for (let index = 0; index < 16 && bits.position + index < bits.bytes.length * 8;
    index += 1) {
    const bit = bits.position + index;
    result |= (((bits.bytes[bit >> 3] ?? 0) >> (bit & 7)) & 1) << index;
  }
  return result;
};

const readLength = (bits: Bits): number | null => {
  const value = peek(bits);
  if (value & 1) return read(bits, 1) === null ? null : 3;
  if (value & 2) return read(bits, 3) === null ? null : ((value >> 2) & 1) + 4;
  if (value & 4) return read(bits, 5) === null ? null : ((value >> 3) & 3) + 6;
  if (value & 8) return read(bits, 7) === null ? null : ((value >> 4) & 7) + 10;
  if (value & 16) return read(bits, 9) === null ? null : ((value >> 5) & 15) + 18;
  if (value & 32) return read(bits, 11) === null ? null : ((value >> 6) & 31) + 34;
  if (value & 64) return read(bits, 13) === null ? null : ((value >> 7) & 63) + 66;
  if (value & 128) return read(bits, 15) === null ? null : ((value >> 8) & 127) + 130;
  if (read(bits, 9) === null || !(value & 256)) return null;
  const extra = read(bits, 8);
  return extra === null ? null : extra + 258;
};

const repeat = (
  bits: Bits, output: Uint8Array, position: number, offset: number
): number | null => {
  const length = readLength(bits);
  if (length === null || offset === 0 || offset > position ||
    length <= 1 || length - 1 > output.length - position) return null;
  for (let index = 0; index < length - 1; index += 1) {
    output[position + index] = output[position + index - offset] ?? 0;
  }
  return position + length - 1;
};

export const decompressMofDs01 = (
  input: Uint8Array, expectedSize: number, issues: string[]
): Uint8Array | null => {
  // The 32 MiB limit bounds allocation on hostile resource headers.
  if (!Number.isSafeInteger(expectedSize) || expectedSize < 0 || expectedSize > 32 * 1024 * 1024) {
    issues.push("Binary MOF decompressed size is invalid or too large.");
    return null;
  }
  const bits: Bits = { bytes: input, position: 0 };
  if (read(bits, 16) !== 0x5344 || read(bits, 16) !== 0x0100) {
    issues.push("Binary MOF DS-01 header is invalid.");
    return null;
  }
  const output = new Uint8Array(expectedSize);
  let position = 0;
  while (position < output.length) {
    const value = peek(bits);
    switch (value & 3) {
      case 1:
      case 2: {
        if (read(bits, 9) === null) break;
        output[position] = ((value >> 2) & 127) | ((value & 3) === 1 ? 128 : 0);
        position += 1;
        continue;
      }
      case 0:
      case 3: {
        const wide = (value & 7) === 7;
        if (read(bits, (value & 3) === 0 ? 8 : wide ? 15 : 11) === null) break;
        const offset = (value & 3) === 0 ? (value >> 2) & 63 :
          wide ? ((value >> 3) & 4095) + 320 : ((value >> 3) & 255) + 64;
        // bmfdec treats 0x113f as a synchronization marker at 512-byte boundaries.
        if (offset === 0x113f && position % 512 === 0) continue;
        const next = repeat(bits, output, position, offset);
        if (next !== null) { position = next; continue; }
        break;
      }
    }
    issues.push("Binary MOF DS-01 stream is truncated or invalid.");
    return null;
  }
  const sync = read(bits, 3);
  if (sync !== 7 || read(bits, 12) !== 4095) {
    issues.push("Binary MOF DS-01 final synchronization marker is invalid.");
    return null;
  }
  return output;
};
