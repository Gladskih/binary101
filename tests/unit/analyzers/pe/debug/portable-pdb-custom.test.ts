import assert from "node:assert/strict";
import { test } from "node:test";
import { ClrHeapReaders } from "../../../../../analyzers/pe/clr/metadata-heaps.js";
import { PortablePdbCustomReader } from "../../../../../analyzers/pe/debug/portable-pdb-custom.js";

const subject = (bytes: Uint8Array) => {
  const issues: string[] = [];
  const heaps = new ClrHeapReaders({ blob: Uint8Array.from([0, bytes.length, ...bytes]),
    strings: null, guid: null, userString: null }, issues);
  return { issues, reader: new PortablePdbCustomReader(heaps, new Map([[0x06, 1], [0x30, 1]])) };
};

void test("Portable PDB custom GUIDs distinguish tuple names from embedded source", async () => {
  // Roslyn PortableCustomDebugInfoKinds: ED9F... is tuple names; 0E8A... is embedded source.
  const tuple = subject(new TextEncoder().encode("item\0"));
  const source = subject(Uint8Array.of(0, 0, 0, 0, 65));

  assert.deepEqual(await tuple.reader.read("ed9fdf71-8879-4747-8ed3-fe5ede3ce710", 1, 0x33),
    { type: "tupleNames", names: ["item"] });
  assert.deepEqual(await source.reader.read("0e8a571b-6926-466e-b4ad-8ab04611f5fe", 1, 0x30),
    { type: "embeddedSource", source: { storage: "raw", bytes: 1, lines: 1, encoding: "UTF-8" } });
  assert.deepEqual(tuple.issues, []);
  assert.deepEqual(source.issues, []);
});

void test("Portable PDB custom records decode text and state payload families", async () => {
  const options = subject(new TextEncoder().encode("language\0CSharp\0"));
  const slots = subject(Uint8Array.of(0));

  assert.deepEqual(await options.reader.read("b5feec05-8cd0-4a83-96da-466284bb4bd8", 1, 0),
    { type: "options", options: [{ name: "language", value: "CSharp" }] });
  assert.deepEqual(await slots.reader.read("755f52a8-91c5-45be-b4b8-209571e552bd", 1, 6),
    { type: "encSlots", slots: 1, temporaries: 1, ordinalSlots: 0 });
});

void test("Portable PDB custom records validate owner kinds without losing payloads", async () => {
  const { reader, issues } = subject(Uint8Array.of(0));

  assert.ok(await reader.read("755f52a8-91c5-45be-b4b8-209571e552bd", 1, 0));
  assert.match(issues.join(" | "), /unexpected parent/);
});

void test("Portable PDB custom records cache decoding and malformed-blob diagnostics", async () => {
  const { reader, issues } = subject(Uint8Array.of(255));
  const kind = "755f52a8-91c5-45be-b4b8-209571e552bd";

  assert.equal(await reader.read(kind, 1, 6), undefined);
  assert.equal(await reader.read(kind, 1, 6), undefined);
  assert.equal(issues.length, 1);
  assert.match(issues.join(" | "), /compressed integer/);
  assert.equal(await reader.read(kind, 127, 6), undefined);
  assert.match(issues.join(" | "), /outside the heap/);
});

void test("Portable PDB permits unknown custom GUIDs and nil kinds as opaque records", async () => {
  const { reader, issues } = subject(new Uint8Array());

  assert.equal(await reader.read("unknown", 1, 0), undefined);
  assert.equal(await reader.read(null, 1, 0), undefined);
  assert.deepEqual(issues, []);
});
