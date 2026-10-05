export const createNativeArrayWideIndexFixture = (header: number, width: number): Uint8Array => {
  const bytes = new Uint8Array(300);
  bytes[0] = header;
  const view = new DataView(bytes.buffer);
  if (width === 2) view.setUint16(1, 256, true);
  else view.setUint32(1, 256, true);
  return bytes;
};

export const createNativeArrayTwoBlockFixture = (width: number): Uint8Array => {
  const second = width === 2 ? 260 : 70000;
  const bytes = new Uint8Array(second + 3);
  const view = new DataView(bytes.buffer);
  bytes[0] = (68 + (width === 2 ? 1 : 2)) * 2; // Seventeen entries; two block indices.
  if (width === 2) {
    view.setUint16(1, 4, true);
    view.setUint16(3, second, true);
  } else {
    view.setUint32(1, 8, true);
    view.setUint32(5, second, true);
  }
  bytes[second + 2] = 42;
  return bytes;
};
