import assert from "node:assert/strict";
import test from "node:test";
import { NativeAotTemplateLayouts } from "../../../../analyzers/native-aot/template-layout.js";
import { NativeAotFunctionReferences } from "../../../../analyzers/native-aot/function-references.js";
import { createFunctionEntryFixture } from "../../../helpers/native-aot-function-map-fixture.js";

void test("template bags expose cctor and dictionary method pointers, ignoring data fields", async () => {
  // Bag: ClassConstructorPointer(index1), DictionaryLayout(relative+4), BaseType(index1), End.
  // Dictionary: one Method cell with explicit pointer(index0).
  const fixture = createFunctionEntryFixture(Uint8Array.of(156, 2, 128, 8, 134, 2, 0, 2, 26, 8, 0, 12, 20));
  fixture.sections.push({ ...fixture.sections[1]!, type: 331 }, { ...fixture.sections[1]!, type: 333 });
  const layouts = new NativeAotTemplateLayouts(fixture.cursor,
    new NativeAotFunctionReferences(fixture.image, fixture.sections, fixture.issues), fixture.issues);

  assert.deepEqual(await layouts.read(0), { classConstructorRva: fixture.codeRvas[1],
    dictionaryMethods: [{ signatureOffset: 9, flags: 4, methodToken: 10,
      entrypointRva: fixture.codeRvas[0] }] });
  assert.equal(fixture.issues.size, 0);
});

void test("template layout caching retains valid fields before duplicate or truncated bag data", async () => {
  const fixture = createFunctionEntryFixture(Uint8Array.of(156, 2, 156, 0, 0));
  fixture.sections.push({ ...fixture.sections[1]!, type: 333 });
  const layouts = new NativeAotTemplateLayouts(fixture.cursor,
    new NativeAotFunctionReferences(fixture.image, fixture.sections, fixture.issues), fixture.issues);

  const first = await layouts.read(0);

  assert.equal(first.classConstructorRva, fixture.codeRvas[1]);
  assert.equal(await layouts.read(0), first);
  assert.match([...fixture.issues].join(" "), /duplicate/);
  assert.deepEqual(await layouts.read(fixture.cursor.reader.size),
    { classConstructorRva: null, dictionaryMethods: [] });
  assert.match([...fixture.issues].join(" "), /outside/);
});

void test("data-valued bag elements are skipped and never resolved as functions", async context => {
  const fixture = createFunctionEntryFixture(Uint8Array.of(134, 0, 156, 0, 0));
  fixture.sections.push({ ...fixture.sections[1]!, type: 333 });
  const reads = context.mock.method(fixture.image, "readData");
  const layouts = new NativeAotTemplateLayouts(fixture.cursor,
    new NativeAotFunctionReferences(fixture.image, fixture.sections, fixture.issues), fixture.issues);

  assert.equal((await layouts.read(0)).classConstructorRva, fixture.codeRvas[0]);
  assert.equal(reads.mock.callCount(), 1);
  assert.equal(fixture.issues.size, 0);
});

void test("different template bags share dictionary decoding and code reference reads", async context => {
  // Two bags point at the same inline dictionary at offset7.
  const fixture = createFunctionEntryFixture(Uint8Array.of(128, 12, 0, 128, 6, 0, 0, 2, 26, 8, 0, 12, 20));
  fixture.sections.push({ ...fixture.sections[1]!, type: 331 });
  const unsigned = context.mock.method(fixture.cursor.reader, "unsigned");
  const layouts = new NativeAotTemplateLayouts(fixture.cursor,
    new NativeAotFunctionReferences(fixture.image, fixture.sections, fixture.issues), fixture.issues);

  const first = await layouts.read(0);
  const decoded = unsigned.mock.callCount();
  const second = await layouts.read(3);

  assert.equal(first.dictionaryMethods, second.dictionaryMethods);
  assert.equal(unsigned.mock.callCount() - decoded, 3);
  assert.equal(fixture.issues.size, 0);
});

void test("dictionary methods without function pointers leave reference tables unread", async context => {
  const fixture = createFunctionEntryFixture(Uint8Array.of(128, 4, 0, 2, 26, 0, 12, 20));
  const reads = context.mock.method(fixture.image, "readData");
  const layouts = new NativeAotTemplateLayouts(fixture.cursor,
    new NativeAotFunctionReferences(fixture.image, fixture.sections, fixture.issues), fixture.issues);

  assert.deepEqual((await layouts.read(0)).dictionaryMethods,
    [{ signatureOffset: 5, flags: 0, methodToken: 10, entrypointRva: null }]);
  assert.equal(reads.mock.callCount(), 0);
  assert.equal(fixture.issues.size, 0);
});

void test("untyped bag-reader failures remain visible", context => {
  const fixture = createFunctionEntryFixture(Uint8Array.of(0));
  context.mock.method(fixture.cursor.reader, "unsigned", () => { throw "untyped failure"; });
  const layouts = new NativeAotTemplateLayouts(fixture.cursor,
    new NativeAotFunctionReferences(fixture.image, fixture.sections, fixture.issues), fixture.issues);

  return layouts.read(0).then(() => {
    assert.deepEqual([...fixture.issues], ["NativeLayout bag read failed."]);
  });
});
