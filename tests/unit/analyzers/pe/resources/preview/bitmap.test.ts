"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { addBitmapPreview } from "../../../../../../analyzers/pe/resources/preview/bitmap.js";
import { createBmpFile } from "../../../../../fixtures/image-sample-files.js";
import { expectDefined } from "../../../../../helpers/expect-defined.js";

void test("addBitmapPreview wraps DIB bytes into an inline BMP preview", () => {
  const bitmapResource = createBmpFile().data.subarray(14);
  const result = addBitmapPreview(bitmapResource, "BITMAP");

  assert.strictEqual(result?.preview?.previewKind, "image");
  assert.strictEqual(result?.preview?.previewMime, "image/bmp");
  assert.match(expectDefined(result?.preview?.previewDataUrl), /^data:image\/bmp;base64,/);
});

void test("addBitmapPreview records an issue for malformed DIB headers", () => {
  const result = addBitmapPreview(new Uint8Array([1, 2, 3, 4]), "BITMAP");

  assert.ok((result?.issues || []).some(issue => /BITMAP resource/i.test(issue)));
});

void test("checks the complete declared DIB header before reading its fields", () => {
  const bytes = new Uint8Array(20);
  new DataView(bytes.buffer).setUint32(0, 40, true); // BITMAPINFOHEADER is 40 bytes.

  assert.match(addBitmapPreview(bytes, "BITMAP")?.issues?.join(" ") ?? "", /BITMAP/);
});

void test("wraps a 32-bit BI_BITFIELDS DIB with three color masks", () => {
  // BITMAPINFOHEADER + three DWORD masks + one DWORD pixel; Microsoft BITMAPINFOHEADER.
  const bytes = new Uint8Array(56);
  const view = new DataView(bytes.buffer);
  view.setUint32(0, 40, true);
  view.setInt32(4, 1, true);
  view.setInt32(8, 1, true);
  view.setUint16(12, 1, true);
  view.setUint16(14, 32, true);
  view.setUint32(16, 3, true); // BI_BITFIELDS
  view.setUint32(40, 0xff0000, true);
  view.setUint32(44, 0xff00, true);
  view.setUint32(48, 0xff, true);
  view.setUint32(52, 0xff0000, true);

  const url = expectDefined(addBitmapPreview(bytes, "BITMAP")?.preview?.previewDataUrl);
  const bitmap = Buffer.from(url.split(",")[1]!, "base64");

  assert.equal(bitmap.readUInt32LE(10), 66); // 14-byte BMP header + 40 + 12.
  assert.equal(bitmap.readUInt32LE(66), 0xff0000);
});

const dibWithPalette = (headerSize: number, bits: number, colors: number, compression: number): Uint8Array => {
  const bytes = new Uint8Array(headerSize + 2048);
  const view = new DataView(bytes.buffer);
  view.setUint32(0, headerSize, true);
  if (headerSize === 12) { view.setUint16(4, 1, true); view.setUint16(6, 1, true);
    view.setUint16(8, 1, true); view.setUint16(10, bits, true); }
  else { view.setInt32(4, 1, true); view.setInt32(8, 1, true); view.setUint16(12, 1, true);
    view.setUint16(14, bits, true); view.setUint32(16, compression, true); view.setUint32(32, colors, true); }
  return bytes;
};
const wrappedBitmap = (data: Uint8Array): DataView => {
  const url = addBitmapPreview(data, "BITMAP")?.preview?.previewDataUrl;
  assert.ok(url);
  const bytes = Uint8Array.from(Buffer.from(url.split(",")[1]!, "base64"));
  return new DataView(bytes.buffer);
};

for (const [size, bits, colors, compression, expected] of [
  [12, 8, 0, 0, 794], [40, 8, 0, 0, 1078], [40, 4, 3, 0, 66],
  [40, 32, 3, 0, 66], [40, 16, 0, 3, 66], [40, 32, 0, 6, 70],
  [52, 32, 0, 3, 66], [56, 32, 0, 6, 70], [108, 32, 0, 3, 122], [124, 32, 0, 0, 138]
]) {
  void test(`wraps DIB header ${size}, ${bits} bpp, palette ${colors}, compression ${compression}`, () => {
    const data = dibWithPalette(size!, bits!, colors!, compression!);
    const view = wrappedBitmap(data);

    assert.equal(view.getUint16(0, true), 0x4d42); // BITMAPFILEHEADER bfType = BM.
    assert.equal(view.getUint32(2, true), data.length + 14);
    assert.equal(view.getUint32(6, true), 0);
    assert.equal(view.getUint32(10, true), expected);
    assert.equal(view.getUint32(14, true), size);
  });
}

void test("rejects unreadable headers and palettes beyond the resource", () => {
  assert.ok(addBitmapPreview(new Uint8Array(3), "BITMAP")?.issues?.length);
  assert.ok(addBitmapPreview(Uint8Array.of(40, 0, 0, 0), "BITMAP")?.issues?.length);
  assert.ok(addBitmapPreview(Uint8Array.of(13, 0, 0, 0, 0), "BITMAP")?.issues?.length);
  assert.ok(addBitmapPreview(dibWithPalette(40, 8, 0xffffffff, 0), "BITMAP")?.issues?.length);
  assert.equal(addBitmapPreview(new Uint8Array(), "ICON"), null);
  assert.equal(wrappedBitmap(dibWithPalette(40, 32, 0, 0).subarray(0, 40)).getUint32(10, true), 54);
});

void test("wraps a compact BITMAPCOREHEADER without reading palette or pixel bytes as header fields", () => {
  const bytes = dibWithPalette(12,24,0,0).subarray(0,15);
  assert.equal(wrappedBitmap(bytes).getUint32(10,true),26);
});
