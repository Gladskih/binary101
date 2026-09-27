const encoder = new TextEncoder();

export const buildLegacyFont = (version = 0x300): Uint8Array => {
  const bytes = new Uint8Array(160);
  const view = new DataView(bytes.buffer);
  view.setUint16(0, version, true);
  view.setUint32(2, bytes.length, true);
  bytes.set(encoder.encode("Fixture copyright"), 6);
  view.setUint16(68, 12, true);
  view.setUint16(70, 96, true);
  view.setUint16(72, 96, true);
  view.setUint16(83, 400, true);
  view.setUint16(88, 16, true);
  bytes[95] = 32;
  bytes[96] = 126;
  view.setUint32(105, 148, true);
  view.setUint32(113, 155, true);
  bytes.set(encoder.encode("Sample\0"), 148);
  return bytes;
};

export const buildFontDirectory = (prefixSize = 113): Uint8Array => {
  const font = buildLegacyFont();
  const names = encoder.encode("\0Sample\0");
  const bytes = new Uint8Array(2 + 2 * (2 + prefixSize + names.length));
  const view = new DataView(bytes.buffer);
  view.setUint16(0, 2, true);
  for (let index = 0; index < 2; index += 1) {
    const pos = 2 + index * (2 + prefixSize + names.length);
    view.setUint16(pos, 100 + index, true);
    bytes.set(font.subarray(0, prefixSize), pos + 2);
    bytes.set(names, pos + 2 + prefixSize);
  }
  return bytes;
};
