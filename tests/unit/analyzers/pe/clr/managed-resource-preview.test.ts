"use strict";

import assert from "node:assert/strict";
import { test, type TestContext } from "node:test";
import type { ManifestXmlDocumentParser } from
  "../../../../../analyzers/pe/resources/preview/manifest-xml.js";
import { parseManifestTestXmlDocument } from "../../../../helpers/manifest-test-parser.js";
import {
  previewManagedResourceBytes, previewManagedResourceText
} from "../../../../../analyzers/pe/clr/managed-resource-preview.js";
import { createPngFile } from "../../../../fixtures/image-sample-files.js";

const encoder = new TextEncoder();

const installXmlParser = (
  context: TestContext, parse: ManifestXmlDocumentParser = parseManifestTestXmlDocument
): void => {
  const descriptor = Object.getOwnPropertyDescriptor(globalThis, "DOMParser");
  Object.defineProperty(globalThis, "DOMParser", { configurable: true,
    value: class { parseFromString(text: string) { return parse(text); } } });
  context.after(() => {
    if (descriptor) Object.defineProperty(globalThis, "DOMParser", descriptor);
    else Reflect.deleteProperty(globalThis, "DOMParser");
  });
};

const utf16Payload = (text: string, encoding: string): Uint8Array => {
  const bytes = new Uint8Array(2 + text.length * 2);
  const view = new DataView(bytes.buffer);
  view.setUint16(0, 0xfeff, encoding === "LE");
  Array.from(text).forEach((character, index) =>
    view.setUint16(2 + index * 2, character.charCodeAt(0), encoding === "LE"));
  return bytes;
};

void test("managed byte previews preserve existing image previews", async () => {
  const result = await previewManagedResourceBytes(createPngFile().data);

  assert.strictEqual(result?.preview?.previewMime, "image/png");
  assert.match(result?.preview?.previewDataUrl ?? "", /^data:image\/png;base64,/);
});

void test("managed text accepts non-ASCII UTF-8", async () => {
  const text = "Привет 世界";

  const result = await previewManagedResourceBytes(encoder.encode(text));

  assert.strictEqual(result?.preview?.textPreview, text);
  assert.strictEqual(result?.preview?.textEncoding, "UTF-8");
});

void test("managed XML preserves the parsed tree", async context => {
  installXmlParser(context);

  const result = await previewManagedResourceBytes(encoder.encode("<settings><value>ok</value></settings>"));

  assert.strictEqual(result?.preview?.previewKind, "xml");
  assert.strictEqual(result?.preview?.xmlTree?.name, "settings");
  assert.strictEqual(result?.issues, undefined);
});

void test("UTF-16LE BOM is recognized without guessing a code page", async () => {
  const result = await previewManagedResourceBytes(utf16Payload("Привет", "LE"));

  assert.strictEqual(result?.preview?.textPreview, "Привет");
  assert.strictEqual(result?.preview?.textEncoding, "UTF-16LE");
});

void test("UTF-16BE BOM is recognized", async () => {
  const result = await previewManagedResourceBytes(utf16Payload("世界", "BE"));

  assert.strictEqual(result?.preview?.textPreview, "世界");
  assert.strictEqual(result?.preview?.textEncoding, "UTF-16BE");
});

void test("invalid encodings and binary control bytes are not shown as text", async () => {
  const invalid = await previewManagedResourceBytes(Uint8Array.of(0xff));
  const binary = await previewManagedResourceBytes(Uint8Array.of(65, 0, 66));
  const empty = await previewManagedResourceBytes(new Uint8Array());

  assert.strictEqual(invalid, null);
  assert.strictEqual(binary, null);
  assert.strictEqual(empty, null);
});

void test("ordinary managed text preserves whitespace", async () => {
  const result = await previewManagedResourceBytes(encoder.encode("first\tvalue\r\nsecond\n"));

  assert.strictEqual(result?.preview?.textPreview, "first\tvalue\r\nsecond\n");
});

void test("large text is detected and preserved beyond the former preview limits", async () => {
  const text = "x".repeat(128 * 1024 + 1) + "end";
  const display = previewManagedResourceText(text);
  const detection = await previewManagedResourceBytes(encoder.encode(text));

  assert.strictEqual(display.preview?.textPreview, text);
  assert.strictEqual(detection?.preview?.textPreview, text);
  assert.strictEqual(display.issues, undefined);
  assert.strictEqual(detection?.issues, undefined);
});

void test("large XML retains its complete structured tree", context => {
  installXmlParser(context);
  const text = "<root><value>" + "x".repeat(32 * 1024 + 1) + "</value><tail/></root>";

  const result = previewManagedResourceText(text);

  assert.strictEqual(result.preview?.previewKind, "xml");
  assert.strictEqual(result.preview?.textPreview, text);
  assert.strictEqual(result.preview?.xmlTree?.children.at(-1)?.name, "tail");
  assert.strictEqual(result.issues, undefined);
});

void test("XML parser failures remain visible with escaped-source data", context => {
  installXmlParser(context, () => { throw new Error("invalid XML"); });

  const result = previewManagedResourceText("<broken>");

  assert.strictEqual(result.preview?.textPreview, "<broken>");
  assert.match(result.issues?.join(" ") ?? "", /invalid XML/);
});

void test("angle-bracket messages are plain text rather than XML", () => {
  const text = "<Path discovery permission to the specified directory was denied.>";

  const result = previewManagedResourceText(text);

  assert.strictEqual(result.preview?.previewKind, "text");
  assert.strictEqual(result.preview?.textPreview, text);
  assert.strictEqual(result.issues, undefined);
});
