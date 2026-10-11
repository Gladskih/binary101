"use strict";

// BinaryReader strings use Encoding.GetString: U+FEFF belongs to the string, not a file BOM.
// https://github.com/dotnet/runtime/blob/main/src/libraries/System.Private.CoreLib/src/System/IO/BinaryReader.cs
const utf8Decoder = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });
const utf16Decoder = new TextDecoder("utf-16le", { fatal: true, ignoreBOM: true });

export const readSevenBitEncodedInt = (
  bytes: Uint8Array,
  offset: number
): { value: number; next: number } | null => {
  if (!Number.isSafeInteger(offset) || offset < 0) return null;
  let result = 0;
  // ResourceReader uses BinaryReader 7-bit encoded integers for resource names and strings:
  // https://github.com/dotnet/runtime/blob/main/src/libraries/System.Private.CoreLib/src/System/Resources/ResourceReader.cs
  for (let shift = 0; shift < 35; shift += 7) {
    const byte = bytes[offset + shift / 7];
    if (byte == null) return null;
    result += (byte & 0x7f) * 2 ** shift;
    if (result > 0xffffffff) return null;
    if ((byte & 0x80) === 0) {
      return {
        value: result > 0x7fffffff ? result - 0x100000000 : result,
        next: offset + shift / 7 + 1
      };
    }
  }
  return null;
};

export const readBinaryString = (
  bytes: Uint8Array,
  offset: number
): { value: string; next: number } | null => {
  const length = readSevenBitEncodedInt(bytes, offset);
  if (!length || length.value < 0 || length.next + length.value > bytes.length) return null;
  try {
    return {
      value: utf8Decoder.decode(bytes.subarray(length.next, length.next + length.value)),
      next: length.next + length.value
    };
  } catch {
    return null;
  }
};

export const readUtf16Name = (
  bytes: Uint8Array,
  offset: number,
  end: number
): { value: string; dataOffsetPosition: number } | null => {
  if (!Number.isSafeInteger(end) || end < 0 || end > bytes.length) return null;
  const length = readSevenBitEncodedInt(bytes.subarray(0, end), offset);
  if (!length || length.value < 0 || length.value % 2 !== 0 ||
      length.next + length.value + 4 > end) return null;
  try {
    return {
      value: utf16Decoder.decode(bytes.subarray(length.next, length.next + length.value)),
      dataOffsetPosition: length.next + length.value
    };
  } catch {
    return null;
  }
};
