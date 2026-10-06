import assert from "node:assert/strict";
import test from "node:test";
import { readStructMarshallingEntry } from "../../../../analyzers/native-aot/struct-marshalling.js";
import { createFunctionEntryFixture } from "../../../helpers/native-aot-function-map-fixture.js";

void test("struct marshalling reads three code fields and leaves the type reference as data", async () => {
  // Type index 0, HasMarshallers + one field, native size 32, three thunk indices 1, name A, offset 4.
  // StructMarshallingStubMapNode.cs, dotnet/runtime v10.0.0.
  const fixture = createFunctionEntryFixture(Uint8Array.of(0, 10, 64, 2, 2, 2, 2, 65, 8));

  assert.deepEqual(await readStructMarshallingEntry(fixture.cursor, fixture.references, fixture.issues),
    { typeIndex: 0, header: 5, nativeSize: 32, marshalRva: fixture.codeRvas[1],
      unmarshalRva: fixture.codeRvas[1], cleanupRva: fixture.codeRvas[1], fields: [{ name: "A", offset: 4 }] });
  assert.equal(fixture.issues.size, 0);
});

void test("invalid-layout structs have no thunks and inconsistent flags are visible", async () => {
  const invalid = createFunctionEntryFixture(Uint8Array.of(0, 4));
  const inconsistent = createFunctionEntryFixture(Uint8Array.of(0, 14));

  assert.equal((await readStructMarshallingEntry(invalid.cursor, invalid.references, invalid.issues)).nativeSize,
    undefined);
  assert.equal(invalid.issues.size, 0);
  assert.equal((await readStructMarshallingEntry(inconsistent.cursor, inconsistent.references,
    inconsistent.issues)).marshalRva, null);
  assert.match([...inconsistent.issues][0]!, /inconsistent/);
});

void test("field-only structs retain a readable prefix of a truncated field table", async () => {
  const fixture = createFunctionEntryFixture(Uint8Array.of(0, 16, 2, 65, 8));

  const parsed = await readStructMarshallingEntry(fixture.cursor, fixture.references, fixture.issues);

  assert.deepEqual(parsed.fields, [{ name: "A", offset: 4 }]);
  assert.equal(parsed.marshalRva, null);
  assert.match([...fixture.issues][0]!, /truncated/);
});

void test("bad UTF-8 field names preserve already validated marshalling code", async () => {
  const fixture = createFunctionEntryFixture(Uint8Array.of(0, 10, 64, 2, 2, 2, 2, 255, 8));

  const parsed = await readStructMarshallingEntry(fixture.cursor, fixture.references, fixture.issues);

  assert.equal(parsed.marshalRva, fixture.codeRvas[1]);
  assert.deepEqual(parsed.fields, []);
  assert.match([...fixture.issues][0]!, /encoded data/);
});

void test("truncated marshalling tuples never resolve a partial list of thunks", async context => {
  const fixture = createFunctionEntryFixture(Uint8Array.of(0, 2, 64, 2));
  const reads = context.mock.method(fixture.image, "readData");

  await assert.rejects(readStructMarshallingEntry(fixture.cursor, fixture.references, fixture.issues), /outside/);
  assert.equal(reads.mock.callCount(), 0);
});

void test("untyped field-reader failures retain their visible warning", async context => {
  const fixture = createFunctionEntryFixture(Uint8Array.of(0, 8, 0, 0));
  context.mock.method(fixture.cursor, "string", () => { throw "untyped failure"; });

  assert.deepEqual((await readStructMarshallingEntry(fixture.cursor, fixture.references, fixture.issues)).fields, []);
  assert.deepEqual([...fixture.issues], ["Struct field decoding failed."]);
});
void test("struct maps check type indices without rejecting readable thunk fields", async () => {
  const fixture = createFunctionEntryFixture(Uint8Array.of(4, 2, 64, 0, 0, 0));

  assert.equal((await readStructMarshallingEntry(fixture.cursor, fixture.references, fixture.issues)).marshalRva,
    fixture.codeRvas[0]);
  assert.deepEqual([...fixture.issues], ["Common fixups data index is outside the table."]);
});
