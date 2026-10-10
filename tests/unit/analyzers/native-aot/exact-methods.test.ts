import assert from "node:assert/strict";
import test from "node:test";
import { readExactMethodEntry } from "../../../../analyzers/native-aot/exact-methods.js";
import { createFunctionEntryFixture } from "../../../helpers/native-aot-function-map-fixture.js";
import { createLegacyLayoutCursor } from "../../../helpers/native-layout-legacy-fixture.js";

void test("legacy exact methods identify the name/signature record in NativeLayoutInfo", async () => {
  const fixture = createFunctionEntryFixture(Uint8Array.of(0, 0, 0, 2));

  assert.deepEqual(await readExactMethodEntry(fixture.cursor, fixture.references,
    createLegacyLayoutCursor(Uint8Array.of(2, 77, 2, 0))),
  { declaringTypeIndex: 0, methodName: "M", methodSignatureOffset: 3,
    genericArgumentIndices: [], entrypointRva: fixture.codeRvas[1] });
});

void test("exact method instantiations resolve the function after the complete metadata signature", async () => {
  const fixture = createFunctionEntryFixture(Uint8Array.of(0, 20, 4, 0, 2, 2));

  assert.deepEqual(await readExactMethodEntry(fixture.cursor, fixture.references),
    { declaringTypeIndex: 0, methodToken: 10, genericArgumentIndices: [0, 1],
      entrypointRva: fixture.codeRvas[1] });
});
void test("exact methods validate both declaring type and instantiation indices", async () => {
  const owner = createFunctionEntryFixture(Uint8Array.of(4, 20, 0, 0));
  const argument = createFunctionEntryFixture(Uint8Array.of(0, 20, 2, 4, 0));

  await readExactMethodEntry(owner.cursor, owner.references);
  await readExactMethodEntry(argument.cursor, argument.references);

  assert.deepEqual([...owner.issues], ["Common fixups data index is outside the table."]);
  assert.deepEqual([...argument.issues], ["Common fixups data index is outside the table."]);
});

void test("exact method truncation never resolves an absent code field", async context => {
  const fixture = createFunctionEntryFixture(Uint8Array.of(0, 20, 2, 0));
  const reads = context.mock.method(fixture.image, "readData");

  await assert.rejects(readExactMethodEntry(fixture.cursor, fixture.references), /outside/);
  assert.equal(reads.mock.callCount(), 0);
});
