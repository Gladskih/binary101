import assert from "node:assert/strict";
import test from "node:test";
import { readNativeAotHashEntries } from "../../../../analyzers/native-aot/hash-map.js";
import { NativeHashtableReader } from "../../../../analyzers/native-aot/native-hashtable.js";
import { createNativeHashtableFixture } from "../../../helpers/native-hashtable-fixture.js";

void test("NativeAOT hash maps decode payloads at referenced offsets", async () => {
  const issues = new Set<string>();

  assert.deepEqual(await readNativeAotHashEntries(createNativeHashtableFixture([
    Uint8Array.of(20), Uint8Array.of(40)]), async cursor => cursor.unsigned(), issues), [10, 20]);
  assert.equal(issues.size, 0);
});

void test("hash maps retain other records after typed and untyped payload failures", async () => {
  const issues = new Set<string>();

  assert.deepEqual(await readNativeAotHashEntries(createNativeHashtableFixture([
    Uint8Array.of(0), Uint8Array.of(2), Uint8Array.of(4)]), async cursor => {
    const value = cursor.unsigned();
    if (!value) throw new Error("bad entry");
    if (value === 1) throw "untyped failure";
    return value;
  }, issues), [2]);
  assert.deepEqual([...issues], ["bad entry", "NativeAOT hash entry decoding failed."]);
});

void test("hash map header truncation produces warnings", async () => {
  const issues = new Set<string>();

  assert.deepEqual(await readNativeAotHashEntries(new Uint8Array(), async cursor => cursor.unsigned(), issues), []);
  assert.match([...issues].join(" "), /outside|truncated/);
});

void test("aliased payload offsets are decoded once", async () => {
  const bytes = createNativeHashtableFixture([Uint8Array.of(2), Uint8Array.of(4)]);
  // The second signed relative offset points at the first payload.
  new DataView(bytes.buffer).setInt32(11, 5, true);
  let decoded = 0;
  const issues = new Set<string>();

  assert.deepEqual(await readNativeAotHashEntries(bytes, async cursor => {
    decoded += 1;
    return cursor.unsigned();
  }, issues), [1]);
  assert.equal(decoded, 1);
});

void test("untyped hash table failures retain a warning", async context => {
  const issues = new Set<string>();
  const bytes = createNativeHashtableFixture([Uint8Array.of(2)]);
  context.mock.method(NativeHashtableReader.prototype, "entries", () => { throw "untyped failure"; });

  const parsed = await readNativeAotHashEntries(bytes, async cursor => cursor.unsigned(), issues);

  assert.deepEqual(parsed, []);
  assert.deepEqual([...issues], ["NativeAOT hash table decoding failed."]);
});
