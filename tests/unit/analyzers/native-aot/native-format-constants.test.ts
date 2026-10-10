import { nativeFormatFixtureKinds as kinds, nativeFormatIntegerBytes, nativeFormatSampleInteger } from
  "../../../helpers/native-format-wire-fixture.js";
import assert from "node:assert/strict";
import test from "node:test";
import { nativeFormatConstantFixture as fixture, createNativeFormatConstantGraph, nativeFormatConstantLeaf,
  createNativeFormatSharedConstantFixture, createNativeFormatCyclicConstantFixture } from
  "../../../helpers/native-format-constant-fixture.js";

void test("constant graphs keep null array positions, shared nodes and cached failures", () => {
  const repeated = createNativeFormatSharedConstantFixture();

  const value = repeated.constants.value(repeated.handle);

  assert.equal(value.type, "object[]");
  assert.ok(Array.isArray(value.value));
  assert.deepEqual(value.value, [{ type: "int", value: 42 }, { type: "int", value: 42 },
    { type: "object", value: null }]);
  assert.equal(value.value[0], value.value[1]);
  assert.equal(repeated.constants.value(repeated.handle), value);
  assert.equal(repeated.warnings.size, 0);
});

void test("deep constant arrays use an explicit worklist without a nesting cap", () => {
  // Stress depth is a test choice, not a format limit: thousands of nested arrays.
  const depth = 2 ** 12;
  const data = createNativeFormatConstantGraph(depth);
  const value = data.constants.value(data.handle);

  assert.deepEqual(nativeFormatConstantLeaf(value, depth), { type: "int", value: 42 });
  assert.equal(data.warnings.size, 0);
});

void test("constant cycles, unsupported kinds and unreadable values warn and stay cached", () => {
  const cycle = createNativeFormatCyclicConstantFixture();
  const unreadable = fixture(kinds.double, [0]);
  const unknown = fixture(kinds.byReference, [0]);

  assert.match(String(cycle.constants.value(cycle.handle).value), /cycle/);
  assert.equal(unreadable.constants.value(unreadable.handle).type, "<invalid>");
  assert.equal(unknown.constants.value(unknown.handle).type, "<invalid>");
  assert.equal(cycle.constants.value(cycle.handle), cycle.constants.value(cycle.handle));
  assert.equal(cycle.warnings.size, 1);
  assert.match([...unreadable.warnings].join(" "), /outside/);
  assert.deepEqual(cycle.constants.value({ type: kinds.string, offset: 0 }), { type: "string", value: null });
});
void test("constant graph warnings contain unexpected decoder failures", context => {
  const data = fixture(kinds.int32, nativeFormatIntegerBytes(nativeFormatSampleInteger));
  context.mock.method(data.store, "record", () => { throw null; });

  assert.deepEqual(data.constants.value(data.handle), { type: "<invalid>", value: "Constant decoding failed." });
  assert.match([...data.warnings].join(" "), /Constant decoding failed/);
});
