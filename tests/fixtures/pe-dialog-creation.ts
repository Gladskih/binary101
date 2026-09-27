export const buildDialogWithCreationData = (kind: "standard" | "extended"): Uint8Array => {
  const bytes = new Uint8Array(128);
  const view = new DataView(bytes.buffer);
  const headerSize = kind === "standard" ? 18 : 26;
  if (kind === "extended") {
    view.setUint16(0, 1, true);
    view.setUint16(2, 0xffff, true);
    view.setUint32(4, 123, true);
  }
  view.setUint16(kind === "standard" ? 8 : 16, 2, true);
  let pos = Math.ceil((headerSize + 6) / 4) * 4;
  for (let index = 0; index < 2; index += 1) {
    const size = kind === "standard" ? 18 : 24;
    if (kind === "extended") view.setUint32(pos, 456 + index, true);
    view.setUint32(pos + (kind === "standard" ? 0 : 8), 0x50010000, true);
    view.setUint16(pos + (kind === "standard" ? 16 : 20), 100 + index, true);
    view.setUint16(pos + size, 0xffff, true);
    view.setUint16(pos + size + 2, 0x82, true); // STATIC class.
    view.setUint16(pos + size + 4, 0xffff, true);
    view.setUint16(pos + size + 6, 0x80, true); // Icon ID, not a BUTTON class.
    // Standard creation-data length includes its WORD; extended length does not.
    view.setUint16(pos + size + 8, kind === "standard" ? 4 : 2, true);
    bytes.set([0xaa, 0xbb], pos + size + 10);
    pos = Math.ceil((pos + size + 12) / 4) * 4;
  }
  return bytes.subarray(0, pos);
};
