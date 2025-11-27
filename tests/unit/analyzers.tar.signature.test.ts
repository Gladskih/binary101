"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { hasTarSignature } from "../../analyzers/tar/index.js";

// Helper to create a DataView for testing
const createDataView = (content: string, offset = 0): DataView => {
  const buffer = new ArrayBuffer(offset + content.length);
  const view = new Uint8Array(buffer);
  for (let i = 0; i < content.length; i++) {
    view[offset + i] = content.charCodeAt(i);
  }
  return new DataView(buffer);
};

void test("hasTarSignature returns true for valid TAR signature", () => {
  const signature = "ustar";
  const dv = createDataView(signature, 257);
  assert.strictEqual(hasTarSignature(dv), true);
});

void test("hasTarSignature returns false for invalid TAR signature", () => {
  const invalidSignature = "not-tar";
  const dv = createDataView(invalidSignature, 257);
  assert.strictEqual(hasTarSignature(dv), false);
});

void test("hasTarSignature returns false for partial TAR signature", () => {
  const partialSignature = "usta"; // Missing 'r'
  const dv = createDataView(partialSignature, 257);
  assert.strictEqual(hasTarSignature(dv), false);
});

void test("hasTarSignature returns false when DataView is too short", () => {
  const dv = createDataView("ustar", 250); // Signature starts at 257, this is too short
  assert.strictEqual(hasTarSignature(dv), false);
});

void test("hasTarSignature returns false when DataView is null or undefined", () => {
  assert.strictEqual(hasTarSignature(null), false);
  assert.strictEqual(hasTarSignature(undefined as unknown as DataView), false);
});

void test("hasTarSignature returns true for empty string at 257 for other reasons", () => {
  const dv = createDataView("", 257);
  assert.strictEqual(hasTarSignature(dv), false);
});
