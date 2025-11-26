"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { readTarString, decodeNullTerminated } from "../../analyzers/tar/helpers.js";

const TEXT_ENCODER = new TextEncoder();

void test("readTarString reads a string correctly", () => {
  const bytes = TEXT_ENCODER.encode("hello world\0\0\0");
  assert.strictEqual(readTarString(bytes, 0, 15), "hello world");
});

void test("readTarString trims trailing spaces by default", () => {
  const bytes = TEXT_ENCODER.encode("hello   \0\0\0");
  assert.strictEqual(readTarString(bytes, 0, 15), "hello");
});

void test("readTarString does not trim trailing spaces when trimSpaces is false", () => {
  const bytes = TEXT_ENCODER.encode("hello   \0\0\0");
  assert.strictEqual(readTarString(bytes, 0, 15, { trimSpaces: false }), "hello   ");
});

void test("readTarString handles empty slice", () => {
  const bytes = TEXT_ENCODER.encode("hello");
  assert.strictEqual(readTarString(bytes, 5, 0), "");
});

void test("readTarString handles slice with only nulls", () => {
  const bytes = new Uint8Array(5).fill(0);
  assert.strictEqual(readTarString(bytes, 0, 5), "");
});

void test("decodeNullTerminated decodes a null-terminated string", () => {
  const bytes = TEXT_ENCODER.encode("hello\0world");
  assert.strictEqual(decodeNullTerminated(bytes), "hello");
});

void test("decodeNullTerminated decodes a string without null terminator", () => {
  const bytes = TEXT_ENCODER.encode("hello world");
  assert.strictEqual(decodeNullTerminated(bytes), "hello world");
});

void test("decodeNullTerminated handles an empty byte array", () => {
  const bytes = new Uint8Array(0);
  assert.strictEqual(decodeNullTerminated(bytes), "");
});

void test("decodeNullTerminated handles an array with only nulls", () => {
  const bytes = new Uint8Array([0, 0, 0]);
  assert.strictEqual(decodeNullTerminated(bytes), "");
});