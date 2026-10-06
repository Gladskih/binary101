import assert from "node:assert/strict";
import test from "node:test";
import { readDelegateMarshallingEntry } from "../../../../analyzers/native-aot/delegate-marshalling.js";
import { createFunctionEntryFixture } from "../../../helpers/native-aot-function-map-fixture.js";

void test("delegate marshalling decodes only its three function entry point indices", async () => {
  const fixture = createFunctionEntryFixture(Uint8Array.of(0, 2, 2, 2));

  assert.deepEqual(await readDelegateMarshallingEntry(fixture.cursor, fixture.references),
    { typeIndex: 0, openStaticRva: fixture.codeRvas[1], closedRva: fixture.codeRvas[1],
      forwardCreationRva: fixture.codeRvas[1] });
});
void test("delegate type indices are checked and truncated tuples do not perform code reads", async context => {
  const invalid = createFunctionEntryFixture(Uint8Array.of(4, 0, 0, 0));
  const short = createFunctionEntryFixture(Uint8Array.of(0, 2, 2));
  const reads = context.mock.method(short.image, "readData");

  assert.equal((await readDelegateMarshallingEntry(invalid.cursor, invalid.references)).typeIndex, 2);
  assert.deepEqual([...invalid.issues], ["Common fixups data index is outside the table."]);
  await assert.rejects(readDelegateMarshallingEntry(short.cursor, short.references), /outside/);
  assert.equal(reads.mock.callCount(), 0);
});
