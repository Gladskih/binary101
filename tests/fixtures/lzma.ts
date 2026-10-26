// Raw FORMAT_RAW streams produced independently with Python's liblzma binding:
// FILTER_LZMA1, dict_size=65536, lc=3, lp=0, pb=2. Both include an end marker.
export const lzmaProperties = [0x5d, 0, 0, 1, 0];
export const lzmaData = Uint8Array.from(Buffer.from("00221046cd69a53c7ffffa6fe000", "hex"));
export const lzmaBinary = Uint8Array.from(Buffer.from("007fbf9b9e8d17fffff6adc000", "hex"));
