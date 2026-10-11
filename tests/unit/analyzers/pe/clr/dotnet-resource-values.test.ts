"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { decodeDotNetResourceValue } from "../../../../../analyzers/pe/clr/dotnet-resource-values.js";

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

void test("v1 Boolean is serialized rather than a v2 primitive", async () => {
  // ResourceReader._LoadObjectV1 does not have a Boolean primitive branch.
  const decoded = await decodeDotNetResourceValue(
    Uint8Array.of(1), { value: 0, next: 0 }, "flag", 1, ["System.Boolean"]
  );

  assert.strictEqual(decoded.opaque, true);
  assert.strictEqual(decoded.value, null);
});

void test("v1 null has no truncation warning", async () => {
  const decoded = await decodeDotNetResourceValue(
    new Uint8Array(), { value: -1, next: 0 }, "empty", 1, []
  );

  assert.strictEqual(decoded.type, "Null");
  assert.strictEqual(decoded.value, null);
  assert.strictEqual(decoded.issues, undefined);
});

void test("Decimal preserves precision and scale", async () => {
  // BinaryReader.ReadDecimal: lo, mid, hi, flags; scale is bits 16..23 of flags.
  const bytes = new Uint8Array(16);
  const view = new DataView(bytes.buffer);
  view.setUint32(0, 12340, true);
  view.setUint32(12, 0x80040000, true);

  const decoded = await decodeDotNetResourceValue(
    bytes, { value: 14, next: 0 }, "amount", 2, []
  );

  assert.strictEqual(decoded.value, "-1.2340");
});

const decodeWideValue = async (typeCode: number, value: bigint, version = 2) => {
  const bytes = new Uint8Array(8);
  new DataView(bytes.buffer).setBigUint64(0, BigInt.asUintN(64, value), true);
  return decodeDotNetResourceValue(bytes, { value: typeCode, next: 0 }, "wide", version,
    ["System.DateTime"]);
};

const decimalCases = [
  { words: [0, 0, 0, 0], value: "0" },
  { words: [0xffffffff, 0xffffffff, 0xffffffff, 0], value: "79228162514264337593543950335" },
  { words: [1, 0, 0, 28 << 16], value: "0.0000000000000000000000000001" },
  { words: [1, 0, 0, 29 << 16], value: null },
  { words: [1, 0, 0, 1], value: null },
  { words: [1, 0, 0, 1 << 24], value: null }
];

for (const [index, item] of decimalCases.entries()) {
  void test(`Decimal validates flags and retains all 96 magnitude bits: ${index}`, async () => {
    const bytes = new Uint8Array(16);
    item.words.forEach((word, offset) => new DataView(bytes.buffer).setUint32(offset * 4, word, true));

    const decoded = await decodeDotNetResourceValue(bytes, { value: 14, next: 0 }, "decimal", 2, []);

    assert.strictEqual(decoded.value, item.value);
    assert.strictEqual(Boolean(decoded.issues?.length), item.value === null);
  });
}

void test("DateTime distinguishes UTC from unspecified and keeps 100ns precision", async () => {
  // DateTime stores ticks since 0001 and kind in bits 62..63 for v2 (FromBinary).
  const decoded = await decodeWideValue(15, 0x4000000000000000n | 621355968000000001n);

  assert.strictEqual(decoded.value, "1970-01-01T00:00:00.0000001Z");
});

void test("v1 DateTime is ticks without kind bits", async () => {
  const decoded = await decodeWideValue(0, 0n, 1);

  assert.strictEqual(decoded.value, "0001-01-01T00:00:00.0000000 (Unspecified)");
});

void test("local DateTime retains its encoded value without assuming a timezone", async () => {
  const decoded = await decodeWideValue(15, 0x8000000000000000n);

  assert.match(String(decoded.value), /Local.*0x8000000000000000/);
});

void test("invalid DateTime ticks are reported", async () => {
  const decoded = await decodeWideValue(15, 3155378976000000000n);

  assert.strictEqual(decoded.value, null);
  assert.ok(decoded.issues?.length);
});

void test("TimeSpan displays signed durations with days and 100ns precision", async () => {
  const decoded = await decodeWideValue(16, -900610000001n);

  assert.strictEqual(decoded.value, "-1.01:01:01.0000001");
});

void test("decodeDotNetResourceValue decodes v2 primitive strings", async () => {
  const payload = makeStringPayload(generatedText(0));
  const decoded = await decodeDotNetResourceValue(
    payload.bytes,
    payload.type,
    generatedName(0),
    2,
    []
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
    []
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
    ["System.Int32"]
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
    []
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
    []
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
    []
  );

  assert.strictEqual(decoded.type, "UserType(64)");
  assert.strictEqual(decoded.opaque, true);
});

// ResourceTypeCode and BinaryReader little-endian primitive storage (ResourceReader.cs).
const numericCases = [
  { code: 3, bytes: [65, 0], expected: "A" },
  { code: 4, bytes: [255], expected: 255 },
  { code: 5, bytes: [255], expected: -1 },
  { code: 6, bytes: [255, 255], expected: -1 },
  { code: 7, bytes: [255, 255], expected: 65535 },
  { code: 9, bytes: [255, 255, 255, 255], expected: 4294967295 },
  { code: 10, bytes: [255, 255, 255, 255, 255, 255, 255, 255], expected: "-1" },
  { code: 11, bytes: [255, 255, 255, 255, 255, 255, 255, 255], expected: "18446744073709551615" },
  { code: 12, bytes: [0, 0, 192, 63], expected: 1.5 },
  { code: 13, bytes: [0, 0, 0, 0, 0, 0, 248, 63], expected: 1.5 }
];

for (const item of numericCases) {
  void test(`numeric resource type ${item.code} decodes exact bits`, async () => {
    const decoded = await decodeDotNetResourceValue(
      Uint8Array.from(item.bytes), { value: item.code, next: 0 }, "number", 2, []
    );

    assert.strictEqual(decoded.value, item.expected);
    assert.strictEqual(decoded.issues, undefined);
  });
}

for (const code of [1, 2, 3, 4, 6, 9, 10, 12, 13, 14, 15, 16, 32, 33]) {
  void test(`truncated primitive type ${code} produces a diagnostic`, async () => {
    const decoded = await decodeDotNetResourceValue(new Uint8Array(),
      { value: code, next: 0 }, "truncated", 2, []);

    assert.strictEqual(decoded.value, null);
    assert.ok(decoded.issues?.length);
  });
}

void test("invalid direct offsets cannot throw a DataView exception", async () => {
  const decoded = await decodeDotNetResourceValue(new Uint8Array(),
    { value: 8, next: -1 }, "bad", 2, []);

  assert.strictEqual(decoded.value, null);
  assert.match(decoded.issues?.join(" ") ?? "", /outside/);
});

void test("large resource strings retain a single complete text source", async () => {
  const xmlText = "<root>" + "x".repeat(32 * 1024 + 1) + "</root>";
  const xml = makeStringPayload(xmlText);
  const large = makeStringPayload("x".repeat(32 * 1024 + 1));

  const structured = await decodeDotNetResourceValue(xml.bytes, xml.type, "xml", 2, []);
  const decoded = await decodeDotNetResourceValue(large.bytes, large.type, "large", 2, []);

  assert.strictEqual(structured.value, xmlText);
  assert.strictEqual(structured.previewKind, "xml");
  assert.strictEqual(structured.textPreview, undefined);
  assert.strictEqual(decoded.value, "x".repeat(32 * 1024 + 1));
  assert.strictEqual(decoded.textPreview, undefined);
  assert.strictEqual(decoded.issues, undefined);
});
