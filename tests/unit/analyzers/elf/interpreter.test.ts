"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { parseElfInterpreter } from "../../../../analyzers/elf/interpreter.js";
import type { ElfProgramHeader } from "../../../../analyzers/elf/types.js";
import { MockFile } from "../../../helpers/mock-file.js";

const makePh = (partial: Partial<ElfProgramHeader>): ElfProgramHeader =>
  ({
    type: 0,
    typeName: null,
    offset: 0n,
    vaddr: 0n,
    paddr: 0n,
    filesz: 0n,
    memsz: 0n,
    flags: 0,
    flagNames: [],
    align: 0n,
    index: 0,
    ...partial
  }) as ElfProgramHeader;

void test("parseElfInterpreter reads PT_INTERP string", async () => {
  const interpreter = "/lib64/ld-linux-x86-64.so.2";
  const bytes = new Uint8Array(128).fill(0);
  const encoded = new TextEncoder().encode(`${interpreter}\0`);
  bytes.set(encoded, 16);
  const file = new MockFile(bytes, "interp.elf", "application/x-elf");
  const programHeaders: ElfProgramHeader[] = [
    makePh({ type: 3, offset: 16n, filesz: BigInt(encoded.length), memsz: BigInt(encoded.length), index: 0 })
  ];

  const parsed = await parseElfInterpreter(file, programHeaders);
  assert.ok(parsed);
  assert.equal(parsed.path, interpreter);
  assert.deepEqual(parsed.issues, []);
});

void test("parseElfInterpreter reports truncation", async () => {
  const bytes = new Uint8Array(32).fill(0);
  bytes.set(new TextEncoder().encode("/ld\0"), 28);
  const file = new MockFile(bytes, "interp-trunc.elf", "application/x-elf");
  const programHeaders: ElfProgramHeader[] = [makePh({ type: 3, offset: 28n, filesz: 16n, memsz: 16n, index: 0 })];

  const parsed = await parseElfInterpreter(file, programHeaders);
  assert.ok(parsed);
  assert.ok(parsed.issues.some(issue => issue.includes("truncated")));
});

const parsePathBytes = (bytes: Uint8Array) => parseElfInterpreter(
  new MockFile(bytes, "interp.elf", "application/x-elf"),
  [makePh({ type: 3, filesz: BigInt(bytes.length) })]
);

void test("ignores another segment type when PT_INTERP is absent", async () => {
  const file = new MockFile(Uint8Array.of(0), "no-interp.elf", "application/x-elf");
  assert.equal(await parseElfInterpreter(file, [makePh({ type: 1, filesz: 1n })]), null);
});

void test("preserves UTF-8 interpreter path text", async () => {
  const path = "/lib/ld-é.so";
  const parsed = await parsePathBytes(new TextEncoder().encode(`${path}\0`));
  assert.deepEqual(parsed, { path, issues: [] });
});

void test("preserves a UTF-8 byte order mark that forms part of the path", async () => {
  const path = "\ufeffrelative.so";
  const parsed = await parsePathBytes(new TextEncoder().encode(`${path}\0`));
  assert.deepEqual(parsed, { path, issues: [] });
});

void test("preserves raw bytes of a non-UTF-8 interpreter path using escapes", async () => {
  // A bare 0xff is not a UTF-8 code unit. ELF permits NUL-terminated pathname bytes.
  const parsed = await parsePathBytes(Uint8Array.of(0x2f, 0xff, 0x5c, 0x01, 0));
  assert.equal(parsed?.path, "/\\xff\\x5c\\x01");
  assert.match(parsed.issues.join(" "), /escaped bytes/);
});

void test("diagnoses a missing interpreter path terminator", async () => {
  const parsed = await parsePathBytes(new TextEncoder().encode("/lib/ld.so"));
  assert.equal(parsed?.path, "/lib/ld.so");
  assert.match(parsed!.issues.join(" "), /NUL.*terminator/);
});

void test("does not use a NUL byte outside the PT_INTERP range", async () => {
  const file = new MockFile(new TextEncoder().encode("/ld\0"), "interp.elf", "application/x-elf");
  const parsed = await parseElfInterpreter(file, [makePh({ type: 3, filesz: 3n })]);
  assert.equal(parsed?.path, "/ld");
  assert.match(parsed.issues.join(" "), /missing its NUL/);
});

void test("diagnoses an empty interpreter path and ignores bytes after its terminator", async () => {
  const parsed = await parsePathBytes(new TextEncoder().encode("\0extra"));
  assert.equal(parsed?.path, "");
  assert.match(parsed.issues.join(" "), /pathname is empty/);
});

for (const span of [{ offset: -1n, filesz: 1n }, { offset: 1n, filesz: 1n },
  { offset: 0n, filesz: 0n }]) {
  void test(`diagnoses an invalid interpreter range ${span.offset}/${span.filesz}`, async () => {
    const file = new MockFile(Uint8Array.of(0), "bad-interp.elf", "application/x-elf");
    const parsed = await parseElfInterpreter(file, [makePh({ type: 3, ...span })]);
    assert.equal(parsed?.path, "");
    assert.match(parsed.issues.join(" "), /empty or falls outside/);
  });
}

void test("bounds an interpreter preview and distinguishes it from a missing terminator", async () => {
  // Bound the requested read even when the segment itself spans much more than one window.
  const bytes = new Uint8Array(256 * 1024).fill(0x61);
  bytes[bytes.length - 1] = 0;
  const parsed = await parsePathBytes(bytes);
  assert.ok(parsed && parsed.path.length < bytes.length - 1);
  assert.match(parsed.issues.join(" "), /preview reached the read limit/);
});

