import assert from "node:assert/strict";
import test from "node:test";
import { nativeFormatConstantFixture as fixture, createNativeFormatConstantGraph, nativeFormatConstantLeaf } from
  "../../../helpers/native-format-constant-fixture.js";

void test("constant graphs keep null array positions, shared nodes and cached failures", () => {
  // Two object-array entries share Int32 record 13: (13 << 7) | 0x11 = 0x691; the third is nil.
  const repeated = fixture(0x0d, [6, 15, 145, 6, 0, 0, 15, 145, 6, 0, 0, 0, 84]);

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
  const data = createNativeFormatConstantGraph(4096);
  const value = data.constants.value(data.handle);

  assert.deepEqual(nativeFormatConstantLeaf(value, 4096), { type: "int", value: 42 });
  assert.equal(data.warnings.size, 0);
});

void test("constant cycles, unsupported kinds and unreadable values warn and stay cached", () => {
  // Generic handle (offset 1 << 7) | ConstantHandleArray (0x0d).
  const cycle = fixture(0x0d, [2, 15, 141, 0, 0, 0]);
  const unreadable = fixture(0x0a, [0]);
  const unknown = fixture(0x02, [0]);

  assert.match(String(cycle.constants.value(cycle.handle).value), /cycle/);
  assert.equal(unreadable.constants.value(unreadable.handle).type, "<invalid>");
  assert.equal(unknown.constants.value(unknown.handle).type, "<invalid>");
  assert.equal(cycle.constants.value(cycle.handle), cycle.constants.value(cycle.handle));
  assert.equal(cycle.warnings.size, 1);
  assert.match([...unreadable.warnings].join(" "), /outside/);
  assert.deepEqual(cycle.constants.value({ type: 0x1a, offset: 0 }), { type: "string", value: null });
});
void test("constant graph warnings contain unexpected decoder failures", context => {
  const data = fixture(0x11, [84]);
  context.mock.method(data.store, "record", () => { throw null; });

  assert.deepEqual(data.constants.value(data.handle), { type: "<invalid>", value: "Constant decoding failed." });
  assert.match([...data.warnings].join(" "), /Constant decoding failed/);
});
