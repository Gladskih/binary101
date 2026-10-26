import assert from "node:assert/strict";
import { test } from "node:test";
import {
  decodeLzmaCoder, getLzmaCoderError, isLzmaMethod
} from "../../../../analyzers/sevenz/lzma-coder.js";
import { lzmaData, lzmaProperties, lzma2Data } from "../../../fixtures/lzma.js";

void test("7z codec selection accepts only LZMA and LZMA2", () => {
  assert.equal(isLzmaMethod("030101"), true);
  assert.equal(isLzmaMethod("21"), true);
  assert.equal(isLzmaMethod("00"), false);
  assert.equal(isLzmaMethod("06f10701"), false);
});

void test("7z dispatch passes raw payload and separate properties to both decoders", async () => {
  assert.deepEqual(await decodeLzmaCoder("030101", lzmaProperties, lzmaData, 4n),
    new TextEncoder().encode("DATA"));
  assert.deepEqual(await decodeLzmaCoder("21", [0], lzma2Data, 4n),
    new TextEncoder().encode("DATA"));
});

void test("7z validates coder property counts and values without initializing WASM", () => {
  assert.equal(getLzmaCoderError("030101", lzmaProperties), undefined);
  assert.equal(getLzmaCoderError("21", [0]), undefined);
  assert.equal(getLzmaCoderError("21", [40]), undefined);
  assert.match(getLzmaCoderError("030101", undefined)!, /LZMA coder properties/);
  assert.match(getLzmaCoderError("030101", [0])!, /LZMA coder properties/);
  assert.match(getLzmaCoderError("21", undefined)!, /LZMA2 coder properties/);
  assert.match(getLzmaCoderError("21", [])!, /LZMA2 coder properties/);
  assert.match(getLzmaCoderError("21", [0, 0])!, /LZMA2 coder properties/);
  assert.match(getLzmaCoderError("21", [41])!, /LZMA2 coder properties/);
  assert.match(getLzmaCoderError("21", [-1])!, /LZMA2 coder properties/);
  assert.match(getLzmaCoderError("21", [0.5])!, /LZMA2 coder properties/);
  assert.match(getLzmaCoderError("00", [])!, /LZMA or LZMA2/);
});

void test("7z dispatch rejects invalid metadata and unsupported coders", async () => {
  await assert.rejects(decodeLzmaCoder("21", [], lzma2Data, 4n), /LZMA2 coder properties/);
  await assert.rejects(decodeLzmaCoder("00", [], lzmaData, 4n), /LZMA or LZMA2/);
});
