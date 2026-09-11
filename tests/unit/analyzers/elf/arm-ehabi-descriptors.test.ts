import assert from "node:assert/strict";
import { test } from "node:test";
import { readArmEhabiDescriptors } from "../../../../analyzers/elf/arm-ehabi-descriptors.js";
import { lsdaFixture } from "../../../fixtures/elf-lsda.js";

void test("reads short EHABI cleanup and catch scopes and terminator", async () => {
  const source = lsdaFixture([4, 0, 2, 0, 8, 0, 0, 0,
    5, 0, 6, 0, 8, 0, 0, 128, 255, 255, 255, 255, 0, 0, 0, 0]);
  const descriptors = await readArmEhabiDescriptors(source.cursorAt(0), 0, 4096n);
  assert.deepEqual(descriptors, [
    { kind: "cleanup", start: 2, length: 4, types: [], landingPad: 4108n },
    { kind: "catch", start: 6, length: 4, types: [0xffffffff], landingPad: 4116n, referenceCatch: true }
  ]);
  assert.deepEqual(source.result.issues, []);
});

void test("reads long exception specifications with an optional landing pad", async () => {
  const source = lsdaFixture([4, 0, 0, 0, 3, 0, 0, 0, 1, 0, 0, 128,
    32, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0]);
  assert.deepEqual(await readArmEhabiDescriptors(source.cursorAt(0), 2, 4096n),
    [{ kind: "exception specification", start: 2, length: 4, types: [32], landingPad: 4116n }]);
});

void test("reports truncated, reserved and zero-length descriptor scopes", async () => {
  const truncated = lsdaFixture([4, 0]);
  assert.deepEqual(await readArmEhabiDescriptors(truncated.cursorAt(0), 0, 0n), []);
  assert.match(truncated.result.issues.join(" "), /Truncated/);
  const reserved = lsdaFixture([5, 0, 3, 0]);
  assert.deepEqual(await readArmEhabiDescriptors(reserved.cursorAt(0), 0, 0n), []);
  assert.match(reserved.result.issues.join(" "), /Reserved/);
  const empty = lsdaFixture([0, 0, 2, 0]);
  assert.deepEqual(await readArmEhabiDescriptors(empty.cursorAt(0), 0, 0n), []);
  assert.match(empty.result.issues.join(" "), /zero/);
});
void test("bounds specification type counts and reports reserved landing pads", async () => {
  const source = lsdaFixture([4, 0, 1, 0, 255, 255, 255, 127]);
  assert.deepEqual(await readArmEhabiDescriptors(source.cursorAt(0), 0, 0n), []);
  assert.match(source.result.issues.join(" "), /bounds or type limit/);
  const cleanup = lsdaFixture([4, 0, 0, 0, 4, 0, 0, 128, 0, 0, 0, 0]);
  assert.equal((await readArmEhabiDescriptors(cleanup.cursorAt(0), 0, 0n))[0]?.landingPad, 8n);
  assert.match(cleanup.result.issues.join(" "), /Reserved high bit/);
  const noLandingPad = lsdaFixture([4, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
  assert.deepEqual(await readArmEhabiDescriptors(noLandingPad.cursorAt(0), 0, 0n),
    [{ kind: "exception specification", start: 0, length: 4, types: [] }]);
});
void test("bounds retained descriptors", async () => {
  // Each short cleanup descriptor is two words; no terminator before the resource ceiling.
  const bytes = Array.from({ length: 100000 }, () => [4, 0, 0, 0, 0, 0, 0, 0]).flat();
  const source = lsdaFixture(bytes);
  assert.equal((await readArmEhabiDescriptors(source.cursorAt(0), 0, 0n)).length, 100000);
  assert.match(source.result.issues.join(" "), /descriptor limit/);
});
