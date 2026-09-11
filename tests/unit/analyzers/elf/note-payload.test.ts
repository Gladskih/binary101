import assert from "node:assert/strict";
import { test } from "node:test";
import { decodeElfNotePayload } from "../../../../analyzers/elf/note-payload.js";
import type { ElfNoteEntry } from "../../../../analyzers/elf/types.js";

const note = (name: string, type: number): ElfNoteEntry => ({ name, type, source: "fixture",
  descSize: 0, typeName: null, description: null, value: null });

void test("decodes GNU ABI versions with either byte order and unknown operating systems", () => {
  const bytes = new Uint8Array(16);
  const view = new DataView(bytes.buffer);
  view.setUint32(4, 6, false);
  view.setUint32(8, 2, false);
  view.setUint32(12, 1, false);
  const entry = note("GNU", 1); // NT_GNU_ABI_TAG (glibc elf.h).
  decodeElfNotePayload(entry, bytes, 4, "big", undefined, []);
  assert.equal(entry.typeName, "NT_GNU_ABI_TAG");
  assert.equal(entry.description, "GNU ABI tag");
  assert.equal(entry.value, "Linux (os=0) version 6.2.1");
  view.setUint32(0, 99, true);
  decodeElfNotePayload(entry, bytes, 4, "little", undefined, []);
  assert.match(entry.value!, /^os=99 version/);
  decodeElfNotePayload(entry, bytes.subarray(0, 15), 4, "little", undefined, []);
  assert.equal(entry.value, null);
});

void test("uses a single GNU registry for build IDs, gold versions and properties", () => {
  const buildId = note("GNU", 3);
  decodeElfNotePayload(buildId, new Uint8Array([0xab, 0xcd]), 8, "little", undefined, []);
  assert.equal(buildId.typeName, "NT_GNU_BUILD_ID");
  assert.equal(buildId.value, "abcd");
  const gold = note("GNU", 4);
  decodeElfNotePayload(gold, new TextEncoder().encode("gold\0"), 8, "little", undefined, []);
  assert.equal(gold.value, "gold");
  decodeElfNotePayload(gold, new Uint8Array(), 8, "little", undefined, []);
  assert.equal(gold.value, null);
  const properties = note("GNU", 5);
  decodeElfNotePayload(properties, new Uint8Array(), 8, "little", undefined, []);
  assert.equal(properties.typeName, "NT_GNU_PROPERTY_TYPE_0");
  assert.deepEqual(properties.properties, []);
});

void test("keeps note namespaces separate and recognizes LINUX core owners", () => {
  const unknown = note("GNU", 99);
  decodeElfNotePayload(unknown, new Uint8Array(), 8, "little", undefined, []);
  assert.equal(unknown.typeName, null);
  const linux = note("LINUX", 6); // NT_AUXV.
  decodeElfNotePayload(linux, new Uint8Array(16), 8, "little", 62, []);
  assert.equal(linux.typeName, "NT_AUXV");
  assert.deepEqual(linux.core?.auxv, [{ tag: 0n, value: 0n }]);
  const vendor = note("vendor", 6);
  decodeElfNotePayload(vendor, new Uint8Array(16), 8, "little", 62, []);
  assert.equal(vendor.core, undefined);
});
