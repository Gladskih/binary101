const unsignedWidth = (value: number): number => {
  if (value < 0x80) return 1;
  if (value < 0x4000) return 2;
  if (value < 0x200000) return 3;
  return value < 0x10000000 ? 4 : 5;
};

// GetLookbackParser uses the canonical width of data << 4, even for noncanonical encodings.
// https://github.com/dotnet/runtime/blob/v10.0.0/src/coreclr/tools/Common/Internal/NativeFormat/NativeFormatReader.Metadata.cs
export const nativeTypeLookbackOffset = (nextOffset: number, data: number): number => {
  return nextOffset - data - unsignedWidth(data * 16) - 2;
};
