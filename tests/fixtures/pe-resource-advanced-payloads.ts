import { createPngFile } from "./image-sample-files.js";

export const joinResourceBytes = (...parts: Uint8Array[]): Uint8Array => {
  const bytes = new Uint8Array(parts.reduce((sum, part) => sum + part.length, 0));
  let offset = 0;
  for (const part of parts) { bytes.set(part, offset); offset += part.length; }
  return bytes;
};

export const resourceDword = (value: number): Uint8Array => {
  const bytes = new Uint8Array(4);
  new DataView(bytes.buffer).setUint32(0, value, true);
  return bytes;
};

export const dfmShortString = (text: string): Uint8Array =>
  joinResourceBytes(Uint8Array.of(text.length), new TextEncoder().encode(text));

export const createDfmResource = (): Uint8Array => joinResourceBytes(
  new TextEncoder().encode("TPF0"), dfmShortString("TForm"), dfmShortString("Main"),
  dfmShortString("ClientWidth"), Uint8Array.of(3, 200, 0),
  dfmShortString("ClientHeight"), Uint8Array.of(2, 120),
  dfmShortString("Caption"), Uint8Array.of(6), dfmShortString("Example"), Uint8Array.of(0),
  dfmShortString("TButton"), dfmShortString("Accept"),
  dfmShortString("Left"), Uint8Array.of(2, 12), dfmShortString("Top"), Uint8Array.of(2, 16),
  dfmShortString("Caption"), Uint8Array.of(6), dfmShortString("OK"), Uint8Array.of(0, 0, 0)
);

export const createEmfRecord = (type: number, payload: Uint8Array): Uint8Array => {
  const bytes = new Uint8Array(Math.ceil((8 + payload.length) / 4) * 4);
  const view = new DataView(bytes.buffer);
  view.setUint32(0, type, true); view.setUint32(4, bytes.length, true); bytes.set(payload, 8);
  return bytes;
};

export const createEmfResource = (
  records = [createEmfRecord(43, joinResourceBytes(resourceDword(10), resourceDword(20),
    resourceDword(90), resourceDword(80)))]
): Uint8Array => {
  // ENHMETAHEADER 88 bytes and EMR_EOF 20 bytes (Windows SDK wingdi.h).
  const header = new Uint8Array(88);
  const eof = createEmfRecord(14, new Uint8Array(12));
  const view = new DataView(header.buffer);
  view.setUint32(0, 1, true); view.setUint32(4, 88, true);
  view.setInt32(16, 100, true); view.setInt32(20, 100, true);
  view.setUint32(40, 0x464d4520, true); view.setUint32(44, 0x10000, true);
  view.setUint32(48, 88 + records.reduce((sum, record) => sum + record.length, 0) + eof.length, true);
  view.setUint32(52, records.length + 2, true); view.setUint16(56, 1, true);
  return joinResourceBytes(header, ...records, eof);
};

export const createWmfRecord = (type: number, payload: Uint8Array): Uint8Array => {
  const bytes = new Uint8Array(Math.ceil((6 + payload.length) / 2) * 2);
  const view = new DataView(bytes.buffer);
  view.setUint32(0, bytes.length / 2, true); view.setUint16(4, type, true); bytes.set(payload, 6);
  return bytes;
};

export const createWmfResource = (
  records = [createWmfRecord(0x041b, Uint8Array.from([100, 0, 100, 0, 0, 0, 0, 0]))]
): Uint8Array => {
  const header = new Uint8Array(18);
  const view = new DataView(header.buffer);
  const eof = createWmfRecord(0, new Uint8Array());
  view.setUint16(0, 1, true); view.setUint16(2, 9, true); view.setUint16(4, 0x300, true);
  view.setUint32(6, (18 + records.reduce((sum, record) => sum + record.length, 0) + eof.length) / 2, true);
  view.setUint16(10, 16, true);
  return joinResourceBytes(header, ...records, eof);
};

export const createPlaceableWmfResource = (): Uint8Array => {
  const header = new Uint8Array(22);
  const view = new DataView(header.buffer);
  view.setUint32(0, 0x9ac6cdd7, true); view.setInt16(10, 100, true); view.setInt16(12, 100, true);
  view.setUint16(14, 1440, true);
  let checksum = 0;
  for (let offset = 0; offset < 20; offset += 2) checksum ^= view.getUint16(offset, true);
  view.setUint16(20, checksum, true);
  return joinResourceBytes(header, createWmfResource());
};

const aniChunk = (id: string, data: Uint8Array): Uint8Array =>
  joinResourceBytes(new TextEncoder().encode(id), resourceDword(data.length), data,
    new Uint8Array(data.length % 2));

const aniCursorFrame = (color: number): Uint8Array => {
  // CUR ICONDIR + ICONDIRENTRY + 1x1 32-bit DIB (XOR row and DWORD-aligned AND row).
  // https://learn.microsoft.com/en-us/windows/win32/menurc/icon-resource
  const bytes = new Uint8Array(22 + 48);
  const view = new DataView(bytes.buffer);
  view.setUint16(2, 2, true); view.setUint16(4, 1, true); bytes[6] = 1; bytes[7] = 1;
  view.setUint32(14, 48, true); view.setUint32(18, 22, true);
  view.setUint32(22, 40, true); view.setInt32(26, 1, true); view.setInt32(30, 2, true);
  view.setUint16(34, 1, true); view.setUint16(36, 32, true); view.setUint32(62, color, true);
  return bytes;
};

export const createAnimatedCursorResource = (): Uint8Array => {
  const header = new Uint8Array(36);
  const view = new DataView(header.buffer);
  view.setUint32(0, 36, true); view.setUint32(4, 2, true); view.setUint32(8, 2, true);
  view.setUint32(28, 6, true); view.setUint32(32, 3, true);
  const body = joinResourceBytes(new TextEncoder().encode("ACON"), aniChunk("anih", header),
    aniChunk("rate", joinResourceBytes(resourceDword(6), resourceDword(12))),
    aniChunk("seq ", joinResourceBytes(resourceDword(1), resourceDword(0))),
    aniChunk("LIST", joinResourceBytes(new TextEncoder().encode("fram"),
      aniChunk("icon", aniCursorFrame(0xffff0000)), aniChunk("icon", aniCursorFrame(0xff0000ff)))));
  return joinResourceBytes(new TextEncoder().encode("RIFF"), resourceDword(body.length), body);
};

export const createAdvancedResourcePayloads = () => [
  { typeId: 10, entryId: 301, langId: 1033, codePage: 0, data: createDfmResource() },
  { typeId: 10, entryId: 302, langId: 1033, codePage: 0, data: createEmfResource() },
  { typeId: 10, entryId: 303, langId: 1033, codePage: 0, data: createPlaceableWmfResource() },
  { typeId: 21, entryId: 304, langId: 1033, codePage: 0, data: createAnimatedCursorResource() },
  { typeId: 10, entryId: 305, langId: 1033, codePage: 65001, data: new TextEncoder().encode(
    '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100"><rect width="100" height="100" fill="red"/></svg>') },
  { typeId: 10, entryId: 306, langId: 1033, codePage: 0, data: createPngFile().data }
];
