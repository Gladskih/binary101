"use strict";

const align = (value: number, alignment: number): number =>
  Math.ceil(value / alignment) * alignment;

const writeUtf16Z = (bytes: Uint8Array, offset: number, text: string): number => {
  const view = new DataView(bytes.buffer);
  for (let index = 0; index < text.length; index += 1) {
    view.setUint16(offset + index * 2, text.charCodeAt(index), true);
  }
  view.setUint16(offset + text.length * 2, 0, true);
  return offset + text.length * 2 + 2;
};

const encodeUtf16Z = (text: string): Uint8Array => {
  const bytes = new Uint8Array((text.length + 1) * 2);
  writeUtf16Z(bytes, 0, text);
  return bytes;
};

const concatBytes = (parts: Uint8Array[]): Uint8Array => {
  const total = parts.reduce((sum, part) => sum + part.length, 0);
  const bytes = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) {
    bytes.set(part, offset);
    offset += part.length;
  }
  return bytes;
};

const buildVersionNode = (
  key: string,
  valueBytes: Uint8Array,
  valueType: 0 | 1,
  children: Uint8Array[]
): Uint8Array => {
  const keyBytes = encodeUtf16Z(key);
  const valueOffset = align(6 + keyBytes.length, 4);
  const valueLength = valueType === 1 ? valueBytes.length / 2 : valueBytes.length;
  const paddedChildren = children.map(child => {
    const padding = align(child.length, 4) - child.length;
    return padding > 0 ? concatBytes([child, new Uint8Array(padding)]) : child;
  });
  const totalLength = valueOffset + valueBytes.length + paddedChildren.reduce(
    (sum, child) => sum + child.length,
    0
  );
  const bytes = new Uint8Array(totalLength).fill(0);
  const view = new DataView(bytes.buffer);
  view.setUint16(0, totalLength, true);
  view.setUint16(2, valueLength, true);
  view.setUint16(4, valueType, true);
  bytes.set(keyBytes, 6);
  bytes.set(valueBytes, valueOffset);
  let offset = valueOffset + valueBytes.length;
  for (const child of paddedChildren) {
    bytes.set(child, offset);
    offset += child.length;
  }
  return bytes;
};

export const buildVersionResource = (): Uint8Array => {
  const fixed = new Uint8Array(52).fill(0);
  const view = new DataView(fixed.buffer);
  view.setUint32(0, 0xfeef04bd, true);
  view.setUint32(4, 0x00010000, true);
  view.setUint32(8, 0x00010002, true);
  view.setUint32(12, 0x00030004, true);
  view.setUint32(16, 0x00010002, true);
  view.setUint32(20, 0x00030004, true);
  const stringTable = buildVersionNode("040904B0", new Uint8Array(), 1, [
    buildVersionNode("CompanyName", encodeUtf16Z("Binary101"), 1, []),
    buildVersionNode("FileDescription", encodeUtf16Z("PE resource showcase"), 1, [])
  ]);
  const translation = (() => {
    const bytes = new Uint8Array(4);
    const translationView = new DataView(bytes.buffer);
    translationView.setUint16(0, 0x0409, true);
    translationView.setUint16(2, 1200, true);
    return buildVersionNode("Translation", bytes, 0, []);
  })();
  return buildVersionNode("VS_VERSION_INFO", fixed, 0, [
    buildVersionNode("StringFileInfo", new Uint8Array(), 1, [stringTable]),
    buildVersionNode("VarFileInfo", new Uint8Array(), 1, [translation])
  ]);
};

export const buildStringTableResource = (): Uint8Array => {
  const bytes = new Uint8Array(48).fill(0);
  const view = new DataView(bytes.buffer);
  view.setUint16(0, 5, true);
  writeUtf16Z(bytes, 2, "Hello");
  view.setUint16(14, 5, true);
  writeUtf16Z(bytes, 16, "World");
  return bytes;
};

export const buildMessageTableResource = (): Uint8Array => {
  const bytes = new Uint8Array(80).fill(0);
  const view = new DataView(bytes.buffer);
  const firstEntryOffset = 32;
  const secondEntryOffset = firstEntryOffset + 6;
  view.setUint32(0, 1, true);
  view.setUint32(4, 10, true);
  view.setUint32(8, 11, true);
  view.setUint32(12, firstEntryOffset, true);
  view.setUint16(firstEntryOffset, 6, true);
  view.setUint16(firstEntryOffset + 2, 0, true);
  bytes[firstEntryOffset + 4] = "O".charCodeAt(0);
  bytes[firstEntryOffset + 5] = "K".charCodeAt(0);
  view.setUint16(secondEntryOffset, 8, true);
  view.setUint16(secondEntryOffset + 2, 1, true);
  writeUtf16Z(bytes, secondEntryOffset + 4, "Hi");
  return bytes;
};
