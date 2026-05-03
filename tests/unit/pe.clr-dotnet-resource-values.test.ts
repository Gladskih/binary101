"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { decodeDotNetResourceValue } from "../../analyzers/pe/clr/dotnet-resource-values.js";

type ResourceValuePayload = {
  bytes: Uint8Array;
  type: { value: number; next: number };
};

// ResourceTypeCode values match System.Resources.ResourceTypeCode in ResourceReader.cs:
// https://github.com/dotnet/runtime/blob/main/src/libraries/System.Private.CoreLib/src/System/Resources/ResourceReader.cs
const RESOURCE_TYPE_CODE_STRING = 1;
const RESOURCE_TYPE_CODE_BOOLEAN = 2;
const RESOURCE_TYPE_CODE_INT32 = 8;
const RESOURCE_TYPE_CODE_BYTE_ARRAY = 32;

const textEncoder = new TextEncoder();
const generatedName = (index: number): string => `resource-${index.toString(36)}`;
const generatedText = (index: number): string => `value-${index.toString(36)}`;
const generatedInt32 = (index: number): number => (index + 1) * Uint16Array.BYTES_PER_ELEMENT ** 8;

const writeSevenBitInt = (value: number): number[] => {
  const bytes: number[] = [];
  let remaining = value;
  do {
    let byte = remaining & 0x7f;
    remaining >>>= 7;
    if (remaining) byte |= 0x80;
    bytes.push(byte);
  } while (remaining);
  return bytes;
};

const readSevenBitInt = (
  bytes: Uint8Array,
  offset: number
): { value: number; next: number } | null => {
  const first = bytes[offset];
  return first == null ? null : { value: first, next: offset + Uint8Array.BYTES_PER_ELEMENT };
};

const makeStringPayload = (value: string): ResourceValuePayload => {
  const encoded = textEncoder.encode(value);
  return {
    bytes: Uint8Array.from([...writeSevenBitInt(encoded.length), ...encoded]),
    type: { value: RESOURCE_TYPE_CODE_STRING, next: 0 }
  };
};

const makeBooleanPayload = (value: boolean): ResourceValuePayload => ({
  bytes: Uint8Array.of(value ? 1 : 0),
  type: { value: RESOURCE_TYPE_CODE_BOOLEAN, next: 0 }
});

const makeInt32Payload = (value: number, version: number): ResourceValuePayload => {
  const bytes = new Uint8Array(Int32Array.BYTES_PER_ELEMENT);
  new DataView(bytes.buffer).setInt32(0, value, true);
  return { bytes, type: { value: version === 1 ? 0 : RESOURCE_TYPE_CODE_INT32, next: 0 } };
};

const makeByteArrayPayload = (payload: Uint8Array): ResourceValuePayload => {
  const bytes = new Uint8Array(Uint32Array.BYTES_PER_ELEMENT + payload.length);
  new DataView(bytes.buffer).setInt32(0, payload.length, true);
  bytes.set(payload, Uint32Array.BYTES_PER_ELEMENT);
  return { bytes, type: { value: RESOURCE_TYPE_CODE_BYTE_ARRAY, next: 0 } };
};

void test("decodeDotNetResourceValue decodes v2 primitive strings", async () => {
  const payload = makeStringPayload(generatedText(0));
  const decoded = await decodeDotNetResourceValue(
    payload.bytes,
    payload.type,
    generatedName(0),
    2,
    [],
    readSevenBitInt
  );

  assert.strictEqual(decoded.name, generatedName(0));
  assert.strictEqual(decoded.type, "String");
  assert.strictEqual(decoded.value, generatedText(0));
  assert.strictEqual(decoded.opaque, false);
});

void test("decodeDotNetResourceValue decodes v2 primitive booleans", async () => {
  const payload = makeBooleanPayload(true);
  const decoded = await decodeDotNetResourceValue(
    payload.bytes,
    payload.type,
    generatedName(1),
    2,
    [],
    readSevenBitInt
  );

  assert.strictEqual(decoded.type, "Boolean");
  assert.strictEqual(decoded.value, true);
});

void test("decodeDotNetResourceValue maps v1 runtime type names to primitive values", async () => {
  const value = generatedInt32(0);
  const payload = makeInt32Payload(value, 1);
  const decoded = await decodeDotNetResourceValue(
    payload.bytes,
    payload.type,
    generatedName(2),
    1,
    ["System.Int32"],
    readSevenBitInt
  );

  assert.strictEqual(decoded.type, "System.Int32");
  assert.strictEqual(decoded.value, value);
  assert.strictEqual(decoded.opaque, false);
});

void test("decodeDotNetResourceValue previews byte-array resources through resource sniffing", async () => {
  const text = JSON.stringify({ value: generatedText(1) });
  const payload = makeByteArrayPayload(textEncoder.encode(text));
  const decoded = await decodeDotNetResourceValue(
    payload.bytes,
    payload.type,
    generatedName(3),
    2,
    [],
    readSevenBitInt
  );

  assert.strictEqual(decoded.type, "ByteArray");
  assert.strictEqual(decoded.value, `${text.length} bytes`);
  assert.strictEqual(decoded.previewKind, "text");
  assert.strictEqual(decoded.textPreview, text);
});

void test("decodeDotNetResourceValue reports truncated primitive values", async () => {
  const decoded = await decodeDotNetResourceValue(
    new Uint8Array(Int32Array.BYTES_PER_ELEMENT - Uint8Array.BYTES_PER_ELEMENT),
    { value: RESOURCE_TYPE_CODE_INT32, next: 0 },
    generatedName(4),
    2,
    [],
    readSevenBitInt
  );

  assert.strictEqual(decoded.value, null);
  assert.ok(decoded.issues?.some(issue => issue.includes("truncated or unsupported")));
});

void test("decodeDotNetResourceValue keeps unknown user types opaque", async () => {
  const decoded = await decodeDotNetResourceValue(
    new Uint8Array(),
    { value: RESOURCE_TYPE_CODE_BYTE_ARRAY * Uint8Array.BYTES_PER_ELEMENT * 2, next: 0 },
    generatedName(5),
    2,
    [],
    readSevenBitInt
  );

  assert.strictEqual(decoded.type, "UserType(64)");
  assert.strictEqual(decoded.opaque, true);
});
