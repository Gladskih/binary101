import assert from "node:assert/strict";
import { test } from "node:test";
import { ElfCoreNoteReader } from "../../../../analyzers/elf/core-note-reader.js";
import { parseElfCoreMappings, parseElfCoreAuxv } from "../../../../analyzers/elf/core-mappings.js";

const mapping = () => {
  const bytes = new Uint8Array(48);
  const view = new DataView(bytes.buffer);
  [1n, 4096n, 0x1000n, 0x3000n, 2n].forEach((value, index) =>
    view.setBigUint64(index * 8, value, true));
  bytes.set(new TextEncoder().encode("/a.so\0"), 40);
  return bytes;
};

void test("reads NT_FILE page offsets and filenames", () => {
  assert.deepEqual(parseElfCoreMappings(new ElfCoreNoteReader(mapping(), 8, "little")), {
    fields: [{ name: "Page size", value: 4096n }],
    mappings: [{ start: 0x1000n, end: 0x3000n, pageOffset: 2n, path: "/a.so" }], issues: []
  });
});

void test("rejects oversized counts and truncated headers", () => {
  const bytes = mapping();
  new DataView(bytes.buffer).setBigUint64(0, 100001n, true);
  assert.match(parseElfCoreMappings(new ElfCoreNoteReader(bytes, 8, "little"))
    .issues.join(" "), /count/);
  new DataView(bytes.buffer).setBigUint64(0, 2n, true);
  assert.match(parseElfCoreMappings(new ElfCoreNoteReader(bytes, 8, "little"))
    .issues.join(" "), /count/);
  assert.match(parseElfCoreMappings(new ElfCoreNoteReader(bytes.subarray(0, 8), 8, "little"))
    .issues.join(" "), /truncated/);
});

void test("warns about inverted ranges and missing filename terminators", () => {
  const bytes = mapping();
  new DataView(bytes.buffer).setBigUint64(24, 0n, true);
  assert.match(parseElfCoreMappings(new ElfCoreNoteReader(bytes, 8, "little"))
    .issues.join(" "), /inverted/);
  assert.match(parseElfCoreMappings(new ElfCoreNoteReader(bytes.subarray(0, 45), 8, "little"))
    .issues.join(" "), /NUL/);
});

void test("bounds auxiliary vectors that exceed the resource limit", () => {
  const bytes = new Uint8Array(800008).fill(1);
  const note = parseElfCoreAuxv(new ElfCoreNoteReader(bytes, 4, "little"));
  assert.equal(note.auxv?.length, 100000);
  assert.match(note.issues.join(" "), /limit/);
});
