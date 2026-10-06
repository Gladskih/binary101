import assert from "node:assert/strict";
import test from "node:test";
import { readClassConstructor } from "../../../../analyzers/native-aot/class-constructors.js";
import { NativeAotFunctionReferences } from "../../../../analyzers/native-aot/function-references.js";
import { createFunctionEntryFixture } from "../../../helpers/native-aot-function-map-fixture.js";

void test("cctor map resolves the pointer immediately preceding the static data base", async () => {
  const fixture = createFunctionEntryFixture(Uint8Array.of(0, 2));
  const staticBase = 0x180;
  fixture.view.setInt32(fixture.fixupsRva + 4, staticBase - fixture.fixupsRva - 4, true);
  fixture.image.readPointerTarget = async address => address === staticBase - 8 ? fixture.codeRvas[1]! : null;
  fixture.image.readPointerValue = async () => 1n;

  assert.deepEqual(await readClassConstructor(fixture.cursor,
    new NativeAotFunctionReferences(fixture.image, fixture.sections, fixture.issues)),
  { typeIndex: 0, staticBaseIndex: 1, entrypointRva: fixture.codeRvas[1] });
  assert.equal(fixture.issues.size, 0);
});
void test("cctor maps validate type references and preserve invalid static base indices", async () => {
  const fixture = createFunctionEntryFixture(Uint8Array.of(4, 4));

  assert.deepEqual(await readClassConstructor(fixture.cursor,
    new NativeAotFunctionReferences(fixture.image, fixture.sections, fixture.issues)),
  { typeIndex: 2, staticBaseIndex: 2, entrypointRva: null });
  assert.deepEqual([...fixture.issues], ["Common fixups data index is outside the table."]);
});

void test("invalid cctor owner indices warn independently of the static data index", async context => {
  const fixture = createFunctionEntryFixture(Uint8Array.of(4, 0));
  const references = new NativeAotFunctionReferences(fixture.image, fixture.sections, fixture.issues);
  context.mock.method(references.data, "pointer", async () => null);

  assert.deepEqual(await readClassConstructor(fixture.cursor, references),
    { typeIndex: 2, staticBaseIndex: 0, entrypointRva: null });
  assert.deepEqual([...fixture.issues], ["Common fixups data index is outside the table."]);
});
