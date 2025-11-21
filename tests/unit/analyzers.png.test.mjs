"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { parsePng } from "../../analyzers/png/index.js";
import {
  createPngFile,
  createPngWithIhdr
} from "../fixtures/sample-files.mjs";
import {
  createInvalidPngSignature,
  createPngMissingIend,
  createTruncatedPngChunk
} from "../fixtures/png-fixtures.mjs";
import { createPngWithManyChunks } from "../fixtures/png-large-chunk.mjs";
import { MockFile } from "../helpers/mock-file.mjs";

const buildChunk = (type, data) => {
  const payload = new Uint8Array(data);
  const chunk = new Uint8Array(8 + payload.length + 4);
  const dv = new DataView(chunk.buffer);
  dv.setUint32(0, payload.length, false);
  chunk.set(Buffer.from(type, "ascii"), 4);
  chunk.set(payload, 8);
  // CRC left as zeroed; parser does not validate it.
  return chunk;
};

const createPngWithAncillaryChunks = () => {
  const ihdrData = new Uint8Array(13);
  const ihdrDv = new DataView(ihdrData.buffer);
  ihdrDv.setUint32(0, 3, false);
  ihdrDv.setUint32(4, 4, false);
  ihdrDv.setUint8(8, 8); // bit depth
  ihdrDv.setUint8(9, 2); // truecolor
  ihdrDv.setUint8(10, 0); // compression
  ihdrDv.setUint8(11, 0); // filter
  ihdrDv.setUint8(12, 0); // interlace

  const phys = new Uint8Array(9);
  const physDv = new DataView(phys.buffer);
  physDv.setUint32(0, 2835, false);
  physDv.setUint32(4, 2835, false);
  physDv.setUint8(8, 1);

  const gamma = new Uint8Array(4);
  new DataView(gamma.buffer).setUint32(0, 45455, false);

  const iccp = Buffer.from([0x73, 0x52, 0x47, 0x42, 0x00, 0x00]);
  const text = Buffer.from("title\u0000hello world", "ascii");
  const trns = new Uint8Array(6).fill(0);
  const idat = new Uint8Array([0x00]);

  const chunks = [
    buildChunk("IHDR", ihdrData),
    buildChunk("pHYs", phys),
    buildChunk("gAMA", gamma),
    buildChunk("iCCP", iccp),
    buildChunk("tEXt", text),
    buildChunk("tRNS", trns),
    buildChunk("IDAT", idat),
    buildChunk("IEND", new Uint8Array(0))
  ];

  const signature = new Uint8Array([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
  const totalLength = signature.length + chunks.reduce((sum, chunk) => sum + chunk.length, 0);
  const bytes = new Uint8Array(totalLength);
  let offset = 0;
  bytes.set(signature, offset);
  offset += signature.length;
  chunks.forEach(chunk => {
    bytes.set(chunk, offset);
    offset += chunk.length;
  });
  return new MockFile(bytes, "ancillary.png", "image/png");
};

test("parsePng rejects invalid signature", async () => {
  const result = await parsePng(createInvalidPngSignature());
  assert.strictEqual(result, null);
});

test("parsePng catches missing IEND and invalid IHDR length", async () => {
  const png = await parsePng(createPngMissingIend());
  assert.ok(png);
  assert.ok(png.issues.some(issue => issue.includes("IHDR length")));
  assert.ok(png.issues.some(issue => issue.includes("IEND chunk missing")));
});

test("parsePng detects truncated chunk", async () => {
  const png = await parsePng(createTruncatedPngChunk());
  assert.ok(png);
  assert.ok(png.issues.some(issue => issue.includes("truncated")));
});

test("parsePng parses small images and chunk metadata", async () => {
  const png = await parsePng(createPngFile());
  assert.ok(png);
  assert.strictEqual(png.ihdr.width, 1);
  assert.strictEqual(png.chunkCount > 0, true);
});

test("parsePng parses IHDR for 2x2 image and reports palette/alpha", async () => {
  const png = await parsePng(createPngWithIhdr());
  assert.ok(png.ihdr);
  assert.strictEqual(png.ihdr.width, 2);
  assert.strictEqual(png.hasTransparency, false);
});

test("parsePng stops after many chunks with warning", async () => {
  const png = await parsePng(createPngWithManyChunks());
  assert.ok(png.issues.some(issue => issue.toLowerCase().includes("truncated")));
});

test("parsePng reads ancillary chunks for metadata", async () => {
  const png = await parsePng(createPngWithAncillaryChunks());
  assert.ok(png.physical);
  assert.ok(png.gamma);
  assert.ok(png.iccProfile);
  assert.ok(png.texts.some(t => t.key === "title"));
  assert.strictEqual(png.hasTransparency, true);
  assert.ok(png.idatChunks > 0);
});
