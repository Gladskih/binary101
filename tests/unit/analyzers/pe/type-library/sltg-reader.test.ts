import assert from "node:assert/strict";
import { test } from "node:test";
import { SltgReader } from "../../../../../analyzers/pe/type-library/sltg-reader.js";

void test("SLTG strings handle empty, null, ANSI text and truncation", () => {
  const data = Uint8Array.from([2, 0, 65, 66, 255, 255, 0, 0]);
  const reader = new SltgReader(data, []);
  assert.deepEqual(reader.string(0), { text: "AB", next: 4 });
  assert.deepEqual(reader.string(4), { text: null, next: 6 });
  assert.deepEqual(reader.string(6), { text: "", next: 8 });
  assert.equal(reader.string(8), null);
  assert.equal(reader.string(2), null);
  assert.equal(reader.stringEnd(0), 4);
  assert.equal(reader.stringEnd(4), 6);
  assert.equal(reader.stringEnd(8), null);
  assert.equal(reader.stringEnd(2), null);
});

void test("SLTG rejects invalid slices", () => {
  const reader = new SltgReader(new Uint8Array(16), []);
  assert.equal(reader.slice(-1, 16).data.length, 0);
  assert.equal(reader.slice(1, 17).data.length, 0);
});

void test("SLTG name cache preserves empty names and rejects unterminated strings", () => {
  const reader = new SltgReader(Uint8Array.from([65, 0, 0, 66]), []);
  assert.equal(reader.name(0), "A");
  assert.equal(reader.name(0), "A");
  assert.equal(reader.name(2), "");
  assert.equal(reader.name(3), null);
  assert.equal(reader.name(-1), null);
  assert.match(reader.issues.join(), /not terminated/);
});

void test("SLTG does not rescan repeatedly referenced unterminated names", context => {
  const reader = new SltgReader(Uint8Array.from([65]), []);
  const search = context.mock.method(reader.data, "indexOf");
  assert.equal(reader.name(0), null);
  assert.equal(reader.name(0), null);
  assert.equal(search.mock.callCount(), 1);
});

for (const text of ["help", null]) {
  void test(`SLTG decodes a shared help stream once (${text})`, context => {
    const reader = new SltgReader(new Uint8Array(1), []);
    const decode = context.mock.fn(() => text);
    reader.helpStrings = { decode };
    assert.equal(reader.help(0), text);
    assert.equal(reader.help(0), text);
    assert.equal(decode.mock.callCount(), 1);
  });
}

void test("SLTG GUID and help references are bounded to their blocks", () => {
  const reader = new SltgReader(new Uint8Array(16), []);
  assert.equal(reader.guid(0), "00000000-0000-0000-0000-000000000000");
  assert.equal(reader.guid(1), null);
  assert.equal(reader.help(0xffff), null);
  assert.equal(reader.help(16), null);
  assert.equal(reader.help(0), null);
  reader.helpStrings = { decode: () => "help" };
  assert.equal(reader.help(0), "help");
});

void test("SLTG subreaders share encoding and reference context", () => {
  const reader = new SltgReader(new Uint8Array(16), []);
  const child = reader.slice(4);
  assert.equal(child.data.length, 12);
  assert.equal(child.decoder, reader.decoder);
  assert.equal(child.references, reader.references);
  assert.equal(reader.range(0.5, 1), false);
  assert.equal(reader.range(0, Infinity), false);
});

void test("SLTG subreaders merge diagnostics and share deduplication", () => {
  const reader = new SltgReader(new Uint8Array(1), ["Existing warning"]);
  const child = reader.slice(0);
  child.warn("Existing warning");
  child.warn("New warning");
  reader.warn("New warning");
  assert.deepEqual(reader.issues, ["Existing warning", "New warning"]);
});
