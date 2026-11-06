import assert from "node:assert/strict";
import { test } from "node:test";
import { readSwfHeader, readSwfMovieHeader, readSwfLzmaHeader } from "../../../../analyzers/swf/header.js";
import { createSwf, createZws } from "../../../fixtures/swf-fixtures.js";

const viewOf = (bytes: Uint8Array): DataView => new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);

void test("readSwfHeader reads the fixed header from a nonzero view offset", () => {
  const swf = createSwf();
  const bytes = new Uint8Array(swf.length + 3);
  bytes.set(swf, 3);

  assert.deepEqual(readSwfHeader(viewOf(bytes.subarray(3))), {
    signature: "FWS", version: 9, fileLength: swf.length
  });
});

for (const signature of ["CWS", "ZWS"]) {
  void test(`readSwfHeader preserves the declared ${signature} compression`, () => {
    const swf = createSwf();
    swf[0] = signature.charCodeAt(0);

    assert.equal(readSwfHeader(viewOf(swf))?.signature, signature);
  });
}

for (const bytes of [createSwf().subarray(0, 7), Uint8Array.of(0, 87, 83, 9, 32, 0, 0, 0),
  Uint8Array.of(70, 87, 0, 9, 32, 0, 0, 0), Uint8Array.of(70, 87, 83, 0, 32, 0, 0, 0),
  Uint8Array.of(70, 87, 83, 9, 13, 0, 0, 0)]) {
  void test(`readSwfHeader rejects malformed prefix ${Buffer.from(bytes).toString("hex")}`, () => {
    assert.equal(readSwfHeader(viewOf(bytes)), null);
  });
}

void test("readSwfMovieHeader decodes signed RECT coordinates and preserves the fixed-point rate", () => {
  // RECT width 2: Xmin=-2, Xmax=1, Ymin=-2, Ymax=1, then byte alignment.
  const bytes = Uint8Array.of(0x14, 0xc8, 0x80, 0x1e, 1, 0);

  assert.deepEqual(readSwfMovieHeader(viewOf(bytes)), {
    movie: { xMin: -2, xMax: 1, yMin: -2, yMax: 1, frameRate: 7808, frameCount: 1 }, tagsOffset: 14
  });
});

for (const bytes of [new Uint8Array(), Uint8Array.of(0), Uint8Array.of(0xf8), new Uint8Array(20).fill(0xf8)]) {
  void test(`readSwfMovieHeader bounds-checks RECT/frame data of length ${bytes.length}`, () => {
    assert.throws(() => readSwfMovieHeader(viewOf(bytes)), /truncated|empty bit width/);
  });
}

void test("readSwfLzmaHeader validates ZWS version, properties and physical compressed extent", () => {
  const zws = createZws();
  const old = zws.slice();
  old[3] = 12;
  const properties = zws.slice();
  properties[12] = 225; // LzmaProps_Decode rejects lc/lp/pb values >= 9*5*5.

  assert.deepEqual(readSwfLzmaHeader(viewOf(zws), zws.length), {
    compressedLength: zws.length - 17, properties: [0x5d, 0, 0, 0x40, 0]
  });
  assert.throws(() => readSwfLzmaHeader(viewOf(zws.subarray(0, 16)), zws.length), /truncated/);
  assert.throws(() => readSwfLzmaHeader(viewOf(old), old.length), /SWF 13/);
  assert.throws(() => readSwfLzmaHeader(viewOf(properties), properties.length), /properties are invalid/);
  assert.throws(() => readSwfLzmaHeader(viewOf(zws), zws.length + 1), /length differs/);
});
