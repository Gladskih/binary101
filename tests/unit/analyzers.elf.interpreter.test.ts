"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { parseElfInterpreter } from "../../analyzers/elf/interpreter.js";
import type { ElfProgramHeader } from "../../analyzers/elf/types.js";
import { MockFile } from "../helpers/mock-file.js";

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

