import assert from "node:assert/strict";
import { test } from "node:test";
import { parseWevtSection } from "../../../../../../analyzers/pe/resources/preview/wevt-sections.js";

const fixture = (): Uint8Array => {
  const bytes = new Uint8Array(128);
  const view = new DataView(bytes.buffer);
  bytes.set(new TextEncoder().encode("LEVL"), 0);
  view.setUint32(4, 24, true); view.setUint32(8, 1, true);
  view.setUint32(12, 4, true); view.setUint32(16, 55, true);
  view.setUint32(20, 96, true);
  view.setUint32(96, 16, true);
  bytes.set(new TextEncoder().encode("E\0r\0r\0o\0r\0"), 100);
  return bytes;
};

void test("reads named WEVT metadata with message ID", () => {
  const issues: string[] = [];
  const section = parseWevtSection(fixture(), 0, 128, issues);
  assert.deepEqual(section.metadata, [
    { kind: "LEVL", id: "4", name: "Error", messageId: 55 }
  ]);
  assert.deepEqual(issues, []);
});

void test("rejects malformed counts and name offsets without throwing", () => {
  const bytes = fixture();
  const issues: string[] = [];
  new DataView(bytes.buffer).setUint32(8, 0xffffffff, true);
  assert.equal(parseWevtSection(bytes, 0, 128, issues).metadata.length, 1);
  assert.ok(issues.length);
  assert.ok(parseWevtSection(bytes, 0, 10, []).metadata.length === 0);
});

void test("reads TEMP field descriptors from a TTBL", () => {
  const bytes = new Uint8Array(128);
  const view = new DataView(bytes.buffer);
  bytes.set(new TextEncoder().encode("TTBL"), 0);
  view.setUint32(4, 72, true); view.setUint32(8, 1, true);
  bytes.set(new TextEncoder().encode("TEMP"), 12);
  view.setUint32(16, 60, true); view.setUint32(20, 1, true);
  view.setUint32(28, 52, true);
  bytes[56] = 7; bytes[57] = 8; view.setUint16(64, 1, true);
  view.setUint32(68, 96, true);
  view.setUint32(96, 8, true);
  bytes.set(new TextEncoder().encode("I\0D\0"), 100);
  const issues: string[] = [];
  const section = parseWevtSection(bytes, 0, 128, issues);
  assert.deepEqual(section.templates[0]?.fields, [
    { name: "ID", inputType: 7, outputType: 8, count: 1, length: 0 }
  ]);
  assert.deepEqual(issues, []);
});

void test("reads CHAN, KEYW and TASK records with their distinct layouts", () => {
  const makeSection = (kind: string, entrySize: number, nameField: number,
    messageField: number): Uint8Array => {
    const bytes = new Uint8Array(128);
    const view = new DataView(bytes.buffer);
    bytes.set(new TextEncoder().encode(kind));
    view.setUint32(4, 12 + entrySize, true);
    view.setUint32(8, 1, true);
    view.setUint32(12, 7, true);
    view.setUint32(12 + nameField, 96, true);
    view.setUint32(12 + messageField, 44, true);
    view.setUint32(96, 8, true);
    bytes.set(new TextEncoder().encode("O\0K\0"), 100);
    return bytes;
  };
  assert.deepEqual(parseWevtSection(makeSection("CHAN", 16, 4, 12), 0, 128, []).metadata,
    [{ kind: "CHAN", id: "7", name: "OK", messageId: 44 }]);
  assert.deepEqual(parseWevtSection(makeSection("KEYW", 16, 12, 8), 0, 128, []).metadata,
    [{ kind: "KEYW", id: "0x7", name: "OK", messageId: 44 }]);
  assert.deepEqual(parseWevtSection(makeSection("TASK", 28, 24, 4), 0, 128, []).metadata,
    [{ kind: "TASK", id: "7", name: "OK", messageId: 44 }]);
});

void test("accepts an empty LEVL table and an absent optional name", () => {
  const bytes = fixture();
  const view = new DataView(bytes.buffer);
  view.setUint32(4, 0, true);
  view.setUint32(8, 0, true);
  const issues: string[] = [];
  assert.deepEqual(parseWevtSection(bytes, 0, 128, issues).metadata, []);
  assert.deepEqual(issues, []);
  view.setUint32(4, 24, true);
  view.setUint32(8, 1, true);
  view.setUint32(20, 0, true);
  assert.equal(parseWevtSection(bytes, 0, 128, issues).metadata[0]?.name, null);
  assert.deepEqual(issues, []);
});

void test("warns on invalid table sizes and truncated TEMP definitions", () => {
  const bytes = fixture();
  const view = new DataView(bytes.buffer);
  view.setUint32(4, 0xffffffff, true);
  const issues: string[] = [];
  assert.deepEqual(parseWevtSection(bytes, 0, 128, issues).metadata, []);
  assert.match(issues[0] ?? "", /section size/);
  bytes.set(new TextEncoder().encode("TTBL"));
  view.setUint32(4, 12, true);
  view.setUint32(8, 1, true);
  issues.length = 0;
  assert.deepEqual(parseWevtSection(bytes, 0, 128, issues).templates, []);
  assert.match(issues[0] ?? "", /templates are truncated/);
});

void test("walks every TEMP entry in a multi-template TTBL", () => {
  const bytes = new Uint8Array(92);
  const view = new DataView(bytes.buffer);
  bytes.set(new TextEncoder().encode("TTBL"));
  view.setUint32(4, 92, true);
  view.setUint32(8, 2, true);
  bytes.set(new TextEncoder().encode("TEMP"), 12);
  view.setUint32(16, 40, true);
  bytes.set(new TextEncoder().encode("TEMP"), 52);
  view.setUint32(56, 40, true);
  const issues: string[] = [];
  const result = parseWevtSection(bytes, 0, 92, issues);
  assert.deepEqual(result.templates.map(template => template.offset), [12, 52]);
  assert.deepEqual(issues, []);
});

void test("rejects a nonempty TEMP field list with a null descriptor offset", () => {
  const bytes = new Uint8Array(52);
  const view = new DataView(bytes.buffer);
  bytes.set(new TextEncoder().encode("TTBL"));
  view.setUint32(4, 52, true);
  view.setUint32(8, 1, true);
  bytes.set(new TextEncoder().encode("TEMP"), 12);
  view.setUint32(16, 40, true);
  view.setUint32(20, 1, true);
  const issues: string[] = [];
  assert.deepEqual(parseWevtSection(bytes, 0, 52, issues).templates[0]?.fields, []);
  assert.match(issues[0] ?? "", /field descriptors are truncated/);
});

void test("validates name lengths and offsets before decoding", () => {
  const bytes = fixture();
  const view = new DataView(bytes.buffer);
  view.setUint32(20, 127, true);
  const invalidOffset: string[] = [];
  assert.equal(parseWevtSection(bytes, 0, 128, invalidOffset).metadata[0]?.name, null);
  assert.deepEqual(invalidOffset, ["WEVT name offset is invalid."]);
  view.setUint32(20, 96, true);
  view.setUint32(96, 5, true);
  const invalidLength: string[] = [];
  assert.equal(parseWevtSection(bytes, 0, 128, invalidLength).metadata[0]?.name, null);
  assert.deepEqual(invalidLength, ["WEVT UTF-16 name is invalid or truncated."]);
  view.setUint32(96, 0xffffffff, true);
  const overrun: string[] = [];
  assert.equal(parseWevtSection(bytes, 0, 128, overrun).metadata[0]?.name, null);
  assert.deepEqual(overrun, ["WEVT UTF-16 name is invalid or truncated."]);
});

void test("rejects section headers outside the manifest and incomplete entries", () => {
  const bytes = fixture();
  const issues: string[] = [];
  assert.deepEqual(parseWevtSection(bytes, 117, 128, issues),
    { metadata: [], templates: [] });
  assert.deepEqual(issues, ["WEVT section header is truncated."]);
  issues.length = 0;
  assert.deepEqual(parseWevtSection(bytes, 0, 129, issues),
    { metadata: [], templates: [] });
  assert.deepEqual(issues, ["WEVT section header is truncated."]);
  issues.length = 0;
  new DataView(bytes.buffer).setUint32(4, 12, true);
  assert.deepEqual(parseWevtSection(bytes, 0, 128, issues),
    { metadata: [], templates: [] });
  assert.deepEqual(issues, ["WEVT LEVL definitions are truncated."]);
});

void test("rejects malformed TEMP signature and size", () => {
  const bytes = new Uint8Array(52);
  const view = new DataView(bytes.buffer);
  bytes.set(new TextEncoder().encode("TTBL"));
  view.setUint32(4, 52, true);
  view.setUint32(8, 1, true);
  bytes.set(new TextEncoder().encode("TEMP"), 12);
  view.setUint32(16, 39, true);
  const invalidSize: string[] = [];
  assert.deepEqual(parseWevtSection(bytes, 0, 52, invalidSize).templates, []);
  assert.deepEqual(invalidSize, ["WEVT TTBL templates are truncated or invalid."]);
  view.setUint32(16, 40, true);
  bytes[12] = 0;
  const invalidSignature: string[] = [];
  assert.deepEqual(parseWevtSection(bytes, 0, 52, invalidSignature).templates, []);
  assert.deepEqual(invalidSignature, ["WEVT TTBL templates are truncated or invalid."]);
});
