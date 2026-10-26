// Raw FORMAT_RAW streams produced independently with Python's liblzma binding:
// FILTER_LZMA1, dict_size=65536, lc=3, lp=0, pb=2. Both include an end marker.
export const lzmaProperties = [0x5d, 0, 0, 1, 0];
export const lzmaData = Uint8Array.from(Buffer.from("00221046cd69a53c7ffffa6fe000", "hex"));
export const lzmaBinary = Uint8Array.from(Buffer.from("007fbf9b9e8d17fffff6adc000", "hex"));
// Python liblzma FORMAT_RAW / FILTER_LZMA2, 4096-byte dictionary, b"DATA" * 1024.
export const lzma2Compressed = Uint8Array.from(Buffer.from(
  "e00fff001e5d00221046cd6edb1bfef537d0e0286b398eb14a62e7fe69f356ca4d51545e4600", "hex"));
export const lzma2Data = Uint8Array.of(1, 0, 3, 68, 65, 84, 65, 0);
