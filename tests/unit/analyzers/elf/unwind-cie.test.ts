import assert from "node:assert/strict";
import { test } from "node:test";
import { readElfUnwindCie } from "../../../../analyzers/elf/unwind-cie.js";
import { unwindCursor } from "../../../fixtures/elf-unwind.js";

void test("reads version 4 address sizes and ULEB return register", async () => {
  const { cursor, issues } = unwindCursor([4, 0, 4, 0, 1, 0x7c, 0x81, 1]);
  const cie = await readElfUnwindCie(cursor, 0, 8, 0n, 3);
  assert.equal(cie?.addressSize, 4);
  assert.equal(cie?.returnRegister, 129n);
  assert.deepEqual(issues, []);
});

void test("reads personality, LSDA encoding and signal-frame augmentations", async () => {
  const { cursor, issues } = unwindCursor([1, 122, 80, 76, 82, 83, 0, 1, 0x78, 16,
    7, 0x83, 0x34, 0x12, 0, 0, 0x1b, 0x1b]);
  const cie = await readElfUnwindCie(cursor, 0, 8, 0n, 62);
  assert.deepEqual(cie?.personality, { address: 0x1234n, indirect: true });
  assert.equal(cie?.lsdaEncoding, 0x1b);
  assert.equal(cie?.fdeEncoding, 0x1b);
  assert.deepEqual(issues, []);
});

void test("rejects unknown versions and segmented addresses", async () => {
  const first = unwindCursor([2]);
  assert.equal(await readElfUnwindCie(first.cursor, 0, 8, 0n, 62), null);
  assert.match(first.issues.join(" "), /version/);
  const second = unwindCursor([4, 0, 8, 1]);
  assert.equal(await readElfUnwindCie(second.cursor, 0, 8, 0n, 62), null);
  assert.match(second.issues.join(" "), /segment/);
});

void test("rejects unsupported legacy augmentation and truncated augmentation", async () => {
  const first = unwindCursor([1, 101, 104, 0, 1, 0x78, 16]);
  assert.equal(await readElfUnwindCie(first.cursor, 0, 8, 0n, 62), null);
  assert.match(first.issues.join(" "), /augmentation/);
  const second = unwindCursor([1, 122, 82, 0, 1, 0x78, 16, 99]);
  assert.equal(await readElfUnwindCie(second.cursor, 0, 8, 0n, 62), null);
  assert.match(second.issues.join(" "), /truncated/);
});

void test("reports missing CIE fields", async () => {
  const { cursor, issues } = unwindCursor([1, 0, 1]);
  assert.equal(await readElfUnwindCie(cursor, 0, 8, 0n, 62), null);
  assert.ok(issues.length > 0);
});
