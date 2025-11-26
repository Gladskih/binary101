"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { enrichResourcePreviews } from "../../dist/analyzers/pe/resources-preview.js";
import { MockFile } from "../helpers/mock-file.js";

const encoder = new TextEncoder();
const pngSmall = Uint8Array.from(
  Buffer.from("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/5+hHgAFgwJ/l7nnMgAAAABJRU5ErkJggg==", "base64")
);

const writeUtf16 = (bytes, offset, text) => {
  for (let i = 0; i < text.length; i += 1) {
    const code = text.charCodeAt(i);
    bytes[offset + i * 2] = code & 0xff;
    bytes[offset + i * 2 + 1] = code >>> 8;
  }
};

test("enrichResourcePreviews builds previews for common PE resources", async () => {
  const fileBytes = new Uint8Array(2000);
  const writeData = (offset, bytes) => {
    fileBytes.set(bytes, offset);
    return { offset, size: bytes.length };
  };

  // Sample resource payloads.
  const icon = writeData(300, pngSmall);

  const groupIconBytes = new Uint8Array(20).fill(0);
  const dvg = new DataView(groupIconBytes.buffer);
  dvg.setUint16(4, 1, true); // idCount
  dvg.setUint8(6, 32);
  dvg.setUint8(7, 32);
  dvg.setUint16(10, 1, true); // planes
  dvg.setUint16(12, 32, true); // bit count
  dvg.setUint32(14, icon.size, true);
  dvg.setUint16(18, 1, true); // icon id matches iconIndex entry
  const groupIcon = writeData(350, groupIconBytes);

  const manifest = writeData(100, encoder.encode('<?xml version="1.0"?><assembly/>'));
  const html = writeData(180, encoder.encode("<html><body>hi</body></html>"));

  const stringTableBytes = new Uint8Array(24).fill(0);
  const dvs = new DataView(stringTableBytes.buffer);
  dvs.setUint16(0, 5, true);
  writeUtf16(stringTableBytes, 2, "Hello");
  dvs.setUint16(12, 6, true); // Declared length longer than remaining bytes to trigger issue
  writeUtf16(stringTableBytes, 14, "Hi");
  const stringTable = writeData(420, stringTableBytes);

  const messageTableBytes = new Uint8Array(80).fill(0);
  const dvm = new DataView(messageTableBytes.buffer);
  dvm.setUint32(0, 1, true); // one block
  dvm.setUint32(4, 10, true); // lowId
  dvm.setUint32(8, 11, true); // highId
  const msgOffset = 32;
  dvm.setUint32(12, msgOffset, true);
  dvm.setUint16(msgOffset + 0, 6, true); // length
  dvm.setUint16(msgOffset + 2, 0, true); // ASCII
  messageTableBytes[msgOffset + 4] = "O".charCodeAt(0);
  messageTableBytes[msgOffset + 5] = "K".charCodeAt(0);
  const nextMsg = msgOffset + 6;
  dvm.setUint16(nextMsg + 0, 8, true);
  dvm.setUint16(nextMsg + 2, 1, true); // unicode
  writeUtf16(messageTableBytes, nextMsg + 4, "Hi");
  const messageTable = writeData(520, messageTableBytes);

  const versionBytes = new Uint8Array(96).fill(0);
  const dvv = new DataView(versionBytes.buffer);
  dvv.setUint16(0, versionBytes.length, true);
  dvv.setUint16(2, 52, true); // valueLength
  dvv.setUint16(4, 0, true); // type
  const key = "VS_VERSION_INFO";
  writeUtf16(versionBytes, 6, key);
  const valueStart = (6 + key.length * 2 + 2 + 3) & ~3;
  dvv.setUint32(valueStart + 0, 0x00010002, true);
  dvv.setUint32(valueStart + 4, 0x00030004, true);
  dvv.setUint32(valueStart + 8, 0x00050006, true);
  dvv.setUint32(valueStart + 12, 0x00070008, true);
  const version = writeData(640, versionBytes);

  const file = new MockFile(fileBytes);

  // Minimal resource directory with one ICON entry to populate iconIndex.
  const directoryBuffer = new ArrayBuffer(128);
  const dirRoot = new DataView(directoryBuffer);
  dirRoot.setUint16(14, 1, true); // one ID entry
  dirRoot.setUint32(16 + 0, 3, true); // id = 3 (ICON)
  dirRoot.setUint32(16 + 4, 0x80000020, true); // subdir at 0x20

  const dirName = new DataView(directoryBuffer, 0x20);
  dirName.setUint16(14, 1, true); // one ID entry
  dirName.setUint32(16 + 0, 1, true); // icon id
  dirName.setUint32(16 + 4, 0x80000040, true); // lang dir at 0x40

  const dirLang = new DataView(directoryBuffer, 0x40);
  dirLang.setUint16(14, 1, true); // one data entry
  dirLang.setUint32(16 + 4, 0x00000060, true); // data entry at 0x60

  const dataEntry = new DataView(directoryBuffer, 0x60);
  dataEntry.setUint32(0, icon.offset, true);
  dataEntry.setUint32(4, icon.size, true);
  dataEntry.setUint32(8, 0, true);
  dataEntry.setUint32(12, 0, true);

  const tree = {
    base: 0,
    limitEnd: directoryBuffer.byteLength,
    top: [],
    detail: [
      { typeName: "ICON", entries: [{ id: 1, langs: [{ lang: 1033, size: icon.size, codePage: 1200, dataRVA: icon.offset }] }] },
      { typeName: "GROUP_ICON", entries: [{ id: 2, langs: [{ lang: 1033, size: groupIcon.size, codePage: 0, dataRVA: groupIcon.offset }] }] },
      { typeName: "MANIFEST", entries: [{ id: 3, langs: [{ lang: null, size: manifest.size, codePage: 65001, dataRVA: manifest.offset }] }] },
      { typeName: "HTML", entries: [{ id: 4, langs: [{ lang: 1031, size: html.size, codePage: 65001, dataRVA: html.offset }] }] },
      { typeName: "STRING", entries: [{ id: 1, langs: [{ lang: 1031, size: stringTable.size, codePage: 1200, dataRVA: stringTable.offset }] }] },
      { typeName: "MESSAGETABLE", entries: [{ id: 5, langs: [{ lang: 2057, size: messageTable.size, codePage: 0, dataRVA: messageTable.offset }] }] },
      { typeName: "VERSION", entries: [{ id: 6, langs: [{ lang: 3082, size: version.size, codePage: 1200, dataRVA: version.offset }] }] }
    ],
    view: async (off, len) => new DataView(directoryBuffer, off, len),
    rvaToOff: value => value
  };

  const result = await enrichResourcePreviews(file, tree);

  const iconLang = result.detail.find(g => g.typeName === "ICON").entries[0].langs[0];
  assert.strictEqual(iconLang.previewKind, "image");
  assert.strictEqual(iconLang.previewMime, "image/png");

  const groupLang = result.detail.find(g => g.typeName === "GROUP_ICON").entries[0].langs[0];
  assert.strictEqual(groupLang.previewKind, "image");
  assert.match(groupLang.previewMime, /x-icon/);

  const manifestLang = result.detail.find(g => g.typeName === "MANIFEST").entries[0].langs[0];
  assert.strictEqual(manifestLang.previewKind, "text");
  assert.match(manifestLang.textPreview, /assembly/);

  const htmlLang = result.detail.find(g => g.typeName === "HTML").entries[0].langs[0];
  assert.strictEqual(htmlLang.previewKind, "html");
  assert.match(htmlLang.textPreview, /<body>hi/);

  const stringLang = result.detail.find(g => g.typeName === "STRING").entries[0].langs[0];
  assert.strictEqual(stringLang.previewKind, "stringTable");
  assert.ok(stringLang.stringTable.length >= 1);
  assert.ok((stringLang.previewIssues || []).length > 0);

  const msgLang = result.detail.find(g => g.typeName === "MESSAGETABLE").entries[0].langs[0];
  assert.strictEqual(msgLang.previewKind, "messageTable");
  assert.ok(msgLang.messageTable.messages.length >= 1);
  assert.strictEqual(msgLang.messageTable.truncated, false);

  const versionLang = result.detail.find(g => g.typeName === "VERSION").entries[0].langs[0];
  assert.strictEqual(versionLang.previewKind, "version");
  assert.ok(versionLang.versionInfo.fixed?.fileVersionString);
});
