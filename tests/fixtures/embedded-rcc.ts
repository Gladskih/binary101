import { deflateSync, zstdCompressSync } from "node:zlib";

// Qt qtbase/src/tools/rcc/rcc.cpp: writeDataBlob, writeDataNames, writeDataInfo.
// https://code.qt.io/cgit/qt/qtbase.git/tree/src/tools/rcc/rcc.cpp
const qtHash = (text: string): number => {
  let hash = 0;
  for (const character of text) {
    hash = ((hash << 4) + character.charCodeAt(0)) >>> 0;
    hash ^= (hash & 0xf0000000) >>> 23;
    hash &= 0x0fffffff;
  }
  return hash;
};

const nameRecord = (name: string): Uint8Array => {
  const bytes = new Uint8Array(6 + name.length * 2);
  const view = new DataView(bytes.buffer);
  view.setUint16(0, name.length);
  view.setUint32(2, qtHash(name));
  Array.from(name).forEach((character, index) => view.setUint16(6 + index * 2, character.charCodeAt(0)));
  return bytes;
};

const dataRecord = (content: Uint8Array): Uint8Array => {
  const bytes = new Uint8Array(4 + content.length);
  new DataView(bytes.buffer).setUint32(0, content.length);
  bytes.set(content, 4);
  return bytes;
};

const compressedMessage = (version: number): Uint8Array => {
  const text = new TextEncoder().encode("Binary101 resource oracle ".repeat(50));
  if (version === 3) return zstdCompressSync(text);
  const compressed = deflateSync(text);
  const bytes = new Uint8Array(4 + compressed.length);
  new DataView(bytes.buffer).setUint32(0, text.length);
  bytes.set(compressed, 4);
  return bytes;
};

const writeFileNode = (view: DataView, offset: number, index: number,
  version: number, firstPayloadSize: number): void => {
  view.setUint16(offset + 4, index === 3 ? version === 3 ? 4 : 1 : 0);
  view.setUint16(offset + 8, 1); // QLocale::C.
  view.setUint32(offset + 10, index === 3 ? 0 : firstPayloadSize);
};

const writeNodes = (view: DataView, treeOffset: number, names: Uint8Array[],
  version: number, firstPayloadSize: number): void => {
  const nodeSize = version === 1 ? 14 : 22;
  let relativeName = 0;
  for (let index = 0; index < 5; index += 1) {
    const offset = treeOffset + index * nodeSize;
    view.setUint32(offset, index === 0 ? 0 : relativeName);
    if (index > 0) relativeName += names[index - 1]!.length;
    if (index < 3) {
      view.setUint16(offset + 4, 2); // RCC directory flag.
      view.setUint32(offset + 6, index === 2 ? 2 : 1);
      view.setUint32(offset + 10, index + 1);
    } else writeFileNode(view, offset, index, version, firstPayloadSize);
    if (nodeSize === 22) view.setBigUint64(offset + 14, 1700000000000n);
  }
};

export const resourceRcc = (version: number): Uint8Array => {
  const data = [dataRecord(compressedMessage(version)),
    dataRecord(new TextEncoder().encode("Qt and GLib resource oracle."))];
  const names = ["org", "binary101", "message.txt", "plain.txt"].map(nameRecord);
  const headerSize = version === 3 ? 24 : 20;
  const nameOffset = headerSize + data.reduce((size, bytes) => size + bytes.length, 0);
  const treeOffset = nameOffset + names.reduce((size, bytes) => size + bytes.length, 0);
  const nodeSize = version === 1 ? 14 : 22;
  const bytes = new Uint8Array(treeOffset + 5 * nodeSize);
  const view = new DataView(bytes.buffer);
  bytes.set(new TextEncoder().encode("qres"));
  view.setUint32(4, version);
  view.setUint32(8, treeOffset);
  view.setUint32(12, headerSize);
  view.setUint32(16, nameOffset);
  if (version === 3) view.setUint32(20, 4);
  let cursor = headerSize;
  for (const record of [...data, ...names]) { bytes.set(record, cursor); cursor += record.length; }
  writeNodes(view, treeOffset, names, version, data[0]!.length);
  return bytes;
};
