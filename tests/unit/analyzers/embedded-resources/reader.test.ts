import assert from "node:assert/strict";
import { test } from "node:test";
import { inspectResource, readResource, requireResource, resourceBytes, validResourceRange }
  from "../../../../analyzers/embedded-resources/reader.js";
import { MockFile } from "../../../helpers/mock-file.js";

void test("checks exact range boundaries, fractions, overflows and negatives", () => {
  assert.equal(validResourceRange(0, 0, 0), true);
  assert.equal(validResourceRange(3, 2, 5), true);
  assert.equal(validResourceRange(3, 3, 5), false);
  assert.equal(validResourceRange(-1, 0, 5), false);
  assert.equal(validResourceRange(0, -1, 5), false);
  assert.equal(validResourceRange(0.5, 1, 5), false);
  assert.equal(validResourceRange(0, 0.5, 5), false);
  assert.equal(validResourceRange(Infinity, 0, 5), false);
  assert.equal(validResourceRange(0, NaN, 5), false);
  assert.equal(validResourceRange(Number.MAX_SAFE_INTEGER + 1, 0, Infinity), false);
});

void test("reads relative bounded views including zero length at the end", async () => {
  const file = new MockFile(new Uint8Array([1, 2, 3, 4]));
  assert.deepEqual(resourceBytes(await readResource(file, { offset: 1, size: 2 }, 1, 1)), new Uint8Array([3]));
  assert.equal((await readResource(file, { offset: 1, size: 2 }, 2, 0)).byteLength, 0);
  await assert.rejects(readResource(file, { offset: 3, size: 2 }, 0, 1), /outside/);
  await assert.rejects(readResource(file, { offset: 1, size: 2 }, 2, 1), /truncated/);
  await assert.rejects(readResource({ size: 5, read: () => Promise.resolve(new DataView(new ArrayBuffer(0))),
    readBytes: () => Promise.resolve(new Uint8Array()) }, { offset: 0, size: 5 }, 0, 2), /read is truncated/);
});

void test("turns errors and non-Error failures into visible diagnostics", async () => {
  assert.doesNotThrow(() => requireResource(1, "valid"));
  assert.throws(() => requireResource(0, "bad"), /bad/);
  assert.deepEqual(await inspectResource(() => Promise.resolve(42)), { value: 42, issues: [] });
  assert.deepEqual(await inspectResource(() => Promise.reject("bad")), { value: null, issues: ["bad"] });
  assert.deepEqual(await inspectResource(() => Promise.reject(new Error("bad"))), { value: null, issues: ["bad"] });
});
