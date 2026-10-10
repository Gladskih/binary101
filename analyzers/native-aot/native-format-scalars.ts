import { NativeFormatError, type NativeFormatReader, type NativeFormatValue } from "./native-format-reader.js";

export type NativeFormatScalarEncoding = "unsigned" | "signed" | "byte" |
  "int64" | "uint64" | "float32" | "float64";
export type NativeFormatScalar = number | string;

// MdBinaryReader.Read overloads define compressed integers and fixed-width floats/bytes.
// https://github.com/dotnet/runtime/blob/v10.0.0/src/coreclr/tools/Common/Internal/Metadata/NativeFormat/MdBinaryReader.cs
const readers: Record<NativeFormatScalarEncoding,
  (reader: NativeFormatReader, offset: number) => NativeFormatValue<NativeFormatScalar>> = {
  unsigned: (reader, offset) => reader.unsigned(offset),
  signed: (reader, offset) => reader.signed(offset),
  byte: (reader, offset) => reader.uint8(offset),
  int64: (reader, offset) => reader.signed64(offset),
  uint64: (reader, offset) => reader.unsigned64(offset),
  float32: (reader, offset) => reader.float32(offset),
  float64: (reader, offset) => reader.float64(offset)
};

export const readNativeFormatScalar = (
  reader: NativeFormatReader, encoding: string, offset: number
): NativeFormatValue<NativeFormatScalar> => {
  const decode = Object.hasOwn(readers, encoding) ? readers[encoding as NativeFormatScalarEncoding] : undefined;
  if (!decode) throw new NativeFormatError(`Unknown NativeFormat scalar encoding ${encoding}.`);
  return decode(reader, offset);
};

export const nativeFormatCollectionScalar = (encoding: string): string =>
  encoding.startsWith("array:") ? encoding.slice(6) : encoding.slice(0, -1);

export const isNativeFormatCollection = (encoding: string): boolean =>
  ["handles", "values", "unsigneds", "signeds"].includes(encoding) || encoding.startsWith("array:");
