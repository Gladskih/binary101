import { deflateRawSync } from "node:zlib";

const utf8 = new TextEncoder();
const align4 = (value: number): number => Math.ceil(value / 4) * 4;

// ECMA-335 II.24.2 metadata root and stream headers. No production constants as oracle.
export const createPortablePdbRoot = (streams: Record<string, Uint8Array>): Uint8Array => {
  const version = utf8.encode("PDB v1.0\0\0\0\0");
  const entries = Object.entries(streams);
  let dataOffset = 16 + version.length + 4 + entries.reduce(
    (size, [name]) => size + 8 + align4(name.length + 1), 0);
  const bytes = new Uint8Array(dataOffset + entries.reduce((size, [, data]) => size + align4(data.length), 0));
  const view = new DataView(bytes.buffer);
  view.setUint32(0, 0x424a5342, true); // BSJB
  view.setUint16(4, 1, true);
  view.setUint16(6, 1, true);
  view.setUint32(12, version.length, true);
  bytes.set(version, 16);
  view.setUint16(16 + version.length + 2, entries.length, true);
  let cursor = 16 + version.length + 4;
  for (const [name, data] of entries) {
    view.setUint32(cursor, dataOffset, true);
    view.setUint32(cursor + 4, align4(data.length), true);
    bytes.set(utf8.encode(`${name}\0`), cursor + 8);
    bytes.set(data, dataOffset);
    cursor += 8 + align4(name.length + 1);
    dataOffset += align4(data.length);
  }
  return bytes;
};

export const createPortablePdbStreams = (): Record<string, Uint8Array> => {
  const blobs = [0];
  const blob = (data: Uint8Array): number => {
    const index = blobs.length;
    blobs.push(data.length, ...data);
    return index;
  };
  const part = blob(utf8.encode("source.cs"));
  const name = blob(Uint8Array.from([47, part]));
  const hash = blob(new Uint8Array(32));
  const points = blob(Uint8Array.from([0, 0, 0, 5, 10, 1, 1, 0, 0]));
  const constant = blob(Uint8Array.from([8, 3, 0, 0, 0])); // LocalConstantSig: int32 value 3.
  const namespace = blob(utf8.encode("System"));
  const imports = blob(Uint8Array.of(1, namespace)); // ImportNamespace, UTF-8 namespace blob index.
  const custom = blob(utf8.encode('{"documents":{"source.cs":"https://example.invalid/source.cs"}}'));
  const pdb = new Uint8Array(40);
  const pdbView = new DataView(pdb.buffer);
  pdbView.setBigUint64(24, 1n | (1n << 6n), true); // Referenced Module and MethodDef tables.
  pdbView.setUint32(32, 1, true);
  pdbView.setUint32(36, 1, true);
  const tables = new Uint8Array(24 + 8 * 4 + 52);
  const view = new DataView(tables.buffer);
  tables.set([2, 0, 0, 1], 4);
  view.setBigUint64(8, 0xffn << 48n, true); // All eight Portable PDB debug tables.
  for (let offset = 24; offset < 56; offset += 4) view.setUint32(offset, 1, true);
  let cursor = 56;
  const word = (value: number): void => { view.setUint16(cursor, value, true); cursor += 2; };
  const dword = (value: number): void => { view.setUint32(cursor, value, true); cursor += 4; };
  [name, 1, hash, 2, 1, points, 1, 1, 1, 1].forEach(word);
  dword(0); dword(8); // LocalScope StartOffset, Length.
  [0, 0, 1, 7, constant, 0, imports, 1, 1, 39, 3, custom].forEach(word);
  // HasCustomDebugInformation Module row 1 is (1 << 5) | 7 = 39.
  const guid = Uint8Array.from([
    0x0f, 0xd0, 0x29, 0x88, 0xb8, 0x11, 0x13, 0x42, 0x87, 0x8b, 0x77, 0x0e, 0x85, 0x97, 0xac, 0x16,
    0xf8, 0x62, 0x51, 0x3f, 0xc6, 0x07, 0xd3, 0x11, 0x90, 0x53, 0, 0xc0, 0x4f, 0xa3, 2, 0xa1,
    0x56, 0x05, 0x11, 0xcc, 0x91, 0xa0, 0x38, 0x4d, 0x9f, 0xec, 0x25, 0xab, 0x9a, 0x35, 0x1a, 0x6a
  ]);
  return { "#Pdb": pdb, "#~": tables, "#Blob": Uint8Array.from(blobs),
    "#GUID": guid, "#Strings": utf8.encode("\0local\0constant\0") };
};

export const createEmbeddedPdbPayload = (image: Uint8Array): Uint8Array => {
  const compressed = deflateRawSync(image);
  const bytes = new Uint8Array(8 + compressed.length);
  bytes.set(new TextEncoder().encode("MPDB"));
  new DataView(bytes.buffer).setUint32(4, image.length, true);
  bytes.set(compressed, 8);
  return bytes;
};
