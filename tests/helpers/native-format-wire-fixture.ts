// Test-side definitions, independent of the analyzer's schema. HandleType values:
// https://github.com/dotnet/runtime/blob/v10.0.0/src/coreclr/tools/Common/Internal/Metadata/NativeFormat/NativeFormatReaderCommonGen.cs
export const nativeFormatFixtureKinds = {
  byReference: 0x02,
  booleanArray: 0x03, boolean: 0x04,
  byteArray: 0x05, byte: 0x06,
  charArray: 0x07, char: 0x08,
  doubleArray: 0x09, double: 0x0a,
  enumArray: 0x0b, enum: 0x0c, handleArray: 0x0d,
  int16Array: 0x0e, int16: 0x0f,
  int32Array: 0x10, int32: 0x11,
  int64Array: 0x12, int64: 0x13, reference: 0x14,
  sbyteArray: 0x15, sbyte: 0x16,
  singleArray: 0x17, single: 0x18,
  stringArray: 0x19, string: 0x1a,
  uint16Array: 0x1b, uint16: 0x1c,
  uint32Array: 0x1d, uint32: 0x1e,
  uint64Array: 0x1f, uint64: 0x20,
  attribute: 0x21, field: 0x23, member: 0x27, method: 0x28,
  namedArgument: 0x2e, namespace: 0x2f, parameter: 0x31, property: 0x33, scope: 0x38,
  qualifiedMethod: 0x36, typeDefinition: 0x3a, typeReference: 0x3d
} as const;

// NativePrimitiveDecoder.DecodeUnsigned/DecodeSigned: 0x0f introduces a
// little-endian 32-bit payload. Using that fixed form avoids fixture byte arithmetic.
// https://github.com/dotnet/runtime/blob/v10.0.0/src/coreclr/tools/Common/Internal/NativeFormat/NativeFormatReader.cs
export const nativeFormatIntegerBytes = (value: number): number[] => {
  const bytes = new Uint8Array(1 + Uint32Array.BYTES_PER_ELEMENT);
  bytes[0] = 0x0f;
  new DataView(bytes.buffer).setUint32(1, value, true);
  return [...bytes];
};

// NativePrimitiveDecoder.DecodeUnsigned's short form has seven payload bits.
export const nativeFormatShortUnsigned = (value: number): number => value * 2;

// Polymorphic handles store HandleType in seven low bits, followed by the offset.
// https://github.com/dotnet/runtime/blob/v10.0.0/src/coreclr/tools/Common/Internal/Metadata/NativeFormat/MdBinaryReader.cs
export const nativeFormatVariantBytes = (type: number, offset: number): number[] =>
  nativeFormatIntegerBytes(offset * 2 ** 7 + type);

// Repeated Int32 value is incidental; share it rather than embedding encoded 84s.
export const nativeFormatSampleInteger = 42;
