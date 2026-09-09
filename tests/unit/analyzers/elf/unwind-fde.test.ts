import assert from "node:assert/strict";
import { test } from "node:test";
import { readElfUnwindFde } from "../../../../analyzers/elf/unwind-fde.js";
import type { ElfUnwindCie } from "../../../../analyzers/elf/unwind-types.js";
import { unwindCursor } from "../../../fixtures/elf-unwind.js";

const cie: ElfUnwindCie = { offset: 0, version: 1, augmentation: "zL", addressSize: 4,
  codeAlignment: 1n, dataAlignment: -4n, returnRegister: 8n, fdeEncoding: 3,
  lsdaEncoding: 3, personality: null, instructions: [] };

void test("reads FDE augmentation LSDA pointer", async () => {
  const { cursor, issues } = unwindCursor([16, 0, 0, 0, 32, 0, 0, 0, 4, 64, 0, 0, 0]);
  const fde = await readElfUnwindFde(cursor, 20, cie, 0n, 3);
  assert.equal(fde?.start?.address, 16n);
  assert.equal(fde?.range, 32n);
  assert.equal(fde?.lsda?.address, 64n);
  assert.deepEqual(issues, []);
});

void test("reads unaugmented FDEs", async () => {
  const { cursor, issues } = unwindCursor([16, 0, 0, 0, 32, 0, 0, 0]);
  const fde = await readElfUnwindFde(cursor, 20, { ...cie, augmentation: "" }, 0n, 3);
  assert.equal(fde?.lsda, null);
  assert.deepEqual(issues, []);
});

void test("rejects negative PC ranges", async () => {
  const { cursor, issues } = unwindCursor([16, 0, 0, 0, 255, 255, 255, 255]);
  assert.equal(await readElfUnwindFde(cursor, 20,
    { ...cie, augmentation: "", fdeEncoding: 11 }, 0n, 3), null);
  assert.match(issues.join(" "), /negative/);
});

void test("reports truncated FDE augmentation", async () => {
  const { cursor, issues } = unwindCursor([16, 0, 0, 0, 32, 0, 0, 0, 10]);
  assert.equal(await readElfUnwindFde(cursor, 20, cie, 0n, 3), null);
  assert.match(issues.join(" "), /augmentation/);
});

void test("rejects an LSDA pointer exceeding its augmentation length", async () => {
  const { cursor, issues } = unwindCursor([16, 0, 0, 0, 32, 0, 0, 0, 1, 64, 0, 0, 0]);
  assert.equal(await readElfUnwindFde(cursor, 20, cie, 0n, 3), null);
  assert.ok(issues.length > 0);
});

void test("reports truncated PC and augmentation length fields", async () => {
  const first = unwindCursor([1]);
  assert.equal(await readElfUnwindFde(first.cursor, 20, cie, 0n, 3), null);
  assert.ok(first.issues.length > 0);
  const second = unwindCursor([16, 0, 0, 0, 32, 0, 0, 0]);
  assert.equal(await readElfUnwindFde(second.cursor, 20, cie, 0n, 3), null);
  assert.ok(second.issues.length > 0);
});
