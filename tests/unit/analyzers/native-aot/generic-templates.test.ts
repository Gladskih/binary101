import assert from "node:assert/strict";
import test from "node:test";
import { readTemplateMethodEntry } from "../../../../analyzers/native-aot/generic-templates.js";
import { NativeFormatCursor } from "../../../../analyzers/native-aot/native-format-cursor.js";
import { NativeFormatReader } from "../../../../analyzers/native-aot/native-format-reader.js";
import { NativeAotCodeReferences } from "../../../../analyzers/native-aot/code-references.js";
import { createNativeAotTemplateFixture } from "../../../helpers/native-aot-function-map-fixture.js";

void test("generic templates resolve their function through NativeReferences rather than CommonFixups", async () => {
  const fixture = createNativeAotTemplateFixture();
  const issues = new Set<string>();
  const layout = new NativeFormatCursor(new NativeFormatReader(fixture.bytes.subarray(0x340, 0x346)), 0);
  const tuple = new NativeFormatCursor(new NativeFormatReader(Uint8Array.of(0, 0)), 0);
  const references = new NativeAotCodeReferences(fixture.image, fixture.sections, issues, 331);

  assert.deepEqual(await readTemplateMethodEntry(tuple, layout, references, new Map()),
    { signatureOffset: 0, layoutOffset: 0, flags: 5, declaringTypeIndex: 0, methodToken: 10,
      genericArgumentIndices: [1], entrypointRva: fixture.codeRvas[1] });
});

void test("aliased template entries decode each shared signature once", async context => {
  const fixture = createNativeAotTemplateFixture();
  const layout = new NativeFormatCursor(new NativeFormatReader(fixture.bytes.subarray(0x340, 0x346)), 0);
  const references = new NativeAotCodeReferences(fixture.image, fixture.sections, new Set(), 331);
  const types = new Map<number, number>();
  const reads = context.mock.method(layout.reader, "unsigned");
  const tuple = (): NativeFormatCursor => new NativeFormatCursor(new NativeFormatReader(Uint8Array.of(0, 0)), 0);

  const first = await readTemplateMethodEntry(tuple(), layout, references, types);
  const decoded = reads.mock.callCount();
  assert.deepEqual(await readTemplateMethodEntry(tuple(), layout, references, types), first);
  assert.equal(reads.mock.callCount(), decoded);
});

void test("shared malformed signatures retain their rejection without being decoded again", async context => {
  const fixture = createNativeAotTemplateFixture();
  const layout = new NativeFormatCursor(new NativeFormatReader(Uint8Array.of(16)), 0);
  const references = new NativeAotCodeReferences(fixture.image, fixture.sections, new Set(), 331);
  const reads = context.mock.method(layout.reader, "unsigned");
  const tuple = (): NativeFormatCursor => new NativeFormatCursor(new NativeFormatReader(Uint8Array.of(0, 0)), 0);

  await assert.rejects(readTemplateMethodEntry(tuple(), layout, references, new Map()), /flags/);
  await assert.rejects(readTemplateMethodEntry(tuple(), layout, references, new Map()), /flags/);
  assert.equal(reads.mock.callCount(), 1);
});

void test("templates without HasFunctionPointer never promote their type reference", async () => {
  const fixture = createNativeAotTemplateFixture();
  const issues = new Set<string>();
  const layout = new NativeFormatCursor(new NativeFormatReader(Uint8Array.of(0, 12, 20, 0)), 0);
  const tuple = new NativeFormatCursor(new NativeFormatReader(Uint8Array.of(0, 6)), 0);

  assert.equal((await readTemplateMethodEntry(tuple, layout,
    new NativeAotCodeReferences(fixture.image, fixture.sections, issues, 331), new Map())).entrypointRva, null);
  assert.equal(issues.size, 0);
});

void test("templates reject offsets beyond their layout and invalid flags", async () => {
  const fixture = createNativeAotTemplateFixture();
  const issues = new Set<string>();
  const layout = new NativeFormatCursor(new NativeFormatReader(Uint8Array.of(16)), 0);
  const references = new NativeAotCodeReferences(fixture.image, fixture.sections, issues, 331);

  await assert.rejects(readTemplateMethodEntry(new NativeFormatCursor(
    new NativeFormatReader(Uint8Array.of(0, 2)), 0), layout, references, new Map()), /outside/);
  await assert.rejects(readTemplateMethodEntry(new NativeFormatCursor(
    new NativeFormatReader(Uint8Array.of(0, 0)), 0), layout, references, new Map()), /flags/);
});
void test("templates validate their external owner and generic type indices", async () => {
  const fixture = createNativeAotTemplateFixture();
  const issues = new Set<string>();
  const references = new NativeAotCodeReferences(fixture.image, fixture.sections, issues, 331);
  const owner = new NativeFormatCursor(new NativeFormatReader(Uint8Array.of(0, 76, 20, 0)), 0);
  const argument = new NativeFormatCursor(new NativeFormatReader(Uint8Array.of(2, 12, 20, 2, 76, 0)), 0);
  const tuple = (): NativeFormatCursor => new NativeFormatCursor(new NativeFormatReader(Uint8Array.of(0, 0)), 0);

  await readTemplateMethodEntry(tuple(), owner, references, new Map());
  assert.deepEqual([...issues], ["Native references data index is outside the table."]);
  issues.clear();
  await readTemplateMethodEntry(tuple(), argument, references, new Map());
  assert.deepEqual([...issues], ["Native references data index is outside the table."]);
});
