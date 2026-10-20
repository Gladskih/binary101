import assert from "node:assert/strict";
import { test } from "node:test";
import { decodeCustomText } from "../../../../../analyzers/pe/debug/portable-pdb-custom-text.js";

void test("Portable PDB decodes Source Link paths and URLs without fetching them", () => {
  const bytes = new TextEncoder().encode('{"documents":{"C:/source/*":"https://example.invalid/*"}}');

  assert.deepEqual(decodeCustomText("sourceLink", bytes), {
    type: "sourceLink", documents: [{ pattern: "C:/source/*", url: "https://example.invalid/*" }]
  });
});

void test("Portable PDB decodes compilation option pairs and preserves empty values", () => {
  const bytes = new TextEncoder().encode("language\0CSharp\0empty\0\0");

  assert.deepEqual(decodeCustomText("options", bytes), { type: "options", options: [
    { name: "language", value: "CSharp" }, { name: "empty", value: "" }
  ] });
});

void test("Portable PDB decodes tuple element names and the VB default namespace", () => {
  assert.deepEqual(decodeCustomText("tupleNames", new TextEncoder().encode("first\0\0last\0")),
    { type: "tupleNames", names: ["first", "", "last"] });
  assert.deepEqual(decodeCustomText("defaultNamespace", new TextEncoder().encode("Example.Namespace")),
    { type: "defaultNamespace", name: "Example.Namespace" });
});

void test("Portable PDB decodes compilation reference names, aliases and identities", () => {
  const head = new TextEncoder().encode("Library.dll\0global,alias\0");
  const bytes = new Uint8Array(head.length + 25);
  bytes.set(head);
  const view = new DataView(bytes.buffer);
  bytes[head.length] = 3; // Assembly reference and embedded interop types flags.
  view.setUint32(head.length + 1, 42, true);
  view.setUint32(head.length + 5, 4096, true);

  assert.deepEqual(decodeCustomText("references", bytes), { type: "references", references: [
    { fileName: "Library.dll", aliases: "global,alias", flags: 3, timeStamp: 42, fileSize: 4096,
      mvid: "00000000-0000-0000-0000-000000000000" }
  ] });
});

[
  { type: "sourceLink", text: "not JSON" },
  { type: "sourceLink", text: "null" },
  { type: "sourceLink", text: "[]" },
  { type: "sourceLink", text: "{}" },
  { type: "sourceLink", text: '{"documents":[]}' },
  { type: "sourceLink", text: '{"documents":{"x":3}}' },
  { type: "sourceLink", text: '{"documents":null}' },
  { type: "sourceLink", text: '{"documents":{}}' },
  { type: "sourceLink", text: '{"documents":{"a*b":"https://example.invalid/*"}}' },
  { type: "sourceLink", text: '{"documents":{"a**":"https://example.invalid/*"}}' },
  { type: "sourceLink", text: '{"documents":{"a*":"https://example.invalid/x"}}' },
  { type: "sourceLink", text: '{"documents":{"a":"https://example.invalid/*"}}' },
  { type: "sourceLink", text: '{"documents":{"a*":"https://example.invalid/**"}}' },
  { type: "sourceLink", text: '{"documents":{"A":"https://example.invalid/a","a":"https://example.invalid/b"}}' },
  { type: "options", text: "name\0" },
  { type: "options", text: "name\0value" },
  { type: "options", text: "name\0value\0name\0again\0" },
  { type: "references", text: "file\0alias\0" },
  { type: "references", text: "file" },
  { type: "tupleNames", text: "unterminated" }
].forEach(({ type, text }) => {
  void test(`Portable PDB rejects malformed ${type} data ${JSON.stringify(text)}`, () => {
    assert.throws(() => decodeCustomText(type, new TextEncoder().encode(text)));
  });
});

void test("Portable PDB rejects invalid UTF-8 and unsupported text record types", () => {
  assert.throws(() => decodeCustomText("defaultNamespace", Uint8Array.of(255)));
  assert.throws(() => decodeCustomText("other", new Uint8Array()), /unsupported/);
  assert.deepEqual(decodeCustomText("options", new Uint8Array()), { type: "options", options: [] });
});
