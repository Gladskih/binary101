import assert from "node:assert/strict";
import test from "node:test";
import { NativeAotCodeReferences } from "../../../../analyzers/native-aot/code-references.js";
import { createNativeAotInvokeFixture } from "../../../helpers/native-aot-invoke-fixture.js";

void test("resolves backward and forward signed common fixups once per index", async context => {
  const fixture = createNativeAotInvokeFixture();
  const issues = new Set<string>();
  const reads = context.mock.method(fixture.image, "readData");
  const refs = new NativeAotCodeReferences(fixture.image, fixture.sections, issues);

  assert.equal(await refs.resolve(0), fixture.codeRvas[0]);
  assert.equal(await refs.resolve(1), fixture.codeRvas[1]);
  assert.equal(await refs.resolve(0), fixture.codeRvas[0]);
  assert.equal(reads.mock.callCount(), 2);
  assert.equal(issues.size, 0);
});

void test("reports missing or ambiguous common fixups", async () => {
  const fixture = createNativeAotInvokeFixture();
  const missing = new Set<string>();
  const ambiguous = new Set<string>();
  const absent = new NativeAotCodeReferences(fixture.image, [], missing);
  const duplicate = new NativeAotCodeReferences(fixture.image,
    [...fixture.sections, fixture.sections[1]!], ambiguous);

  assert.equal(await absent.resolve(0), null);
  assert.equal(await duplicate.resolve(0), null);
  assert.match([...missing].join(" "), /missing or ambiguous/);
  assert.match([...ambiguous].join(" "), /missing or ambiguous/);
});

void test("rejects invalid and out-of-table reference indices", async () => {
  const fixture = createNativeAotInvokeFixture();
  const issues = new Set<string>();
  const refs = new NativeAotCodeReferences(fixture.image, fixture.sections, issues);

  assert.equal(await refs.resolve(-1), null);
  assert.equal(await refs.resolve(0.5), null);
  assert.equal(await refs.resolve(2), null);
  assert.match([...issues].join(" "), /outside the table/);
});

void test("rejects a fixup table with an unknown size", async () => {
  const fixture = createNativeAotInvokeFixture();
  fixture.sections[1]!.size = null;
  const issues = new Set<string>();

  assert.equal(await new NativeAotCodeReferences(fixture.image, fixture.sections, issues).resolve(0), null);
  assert.match([...issues].join(" "), /outside the table/);
});

void test("retains complete pointers before an incomplete table tail", async () => {
  const fixture = createNativeAotInvokeFixture();
  fixture.sections[1]!.size = 9;
  const issues = new Set<string>();

  assert.equal(await new NativeAotCodeReferences(fixture.image, fixture.sections, issues).resolve(1),
    fixture.codeRvas[1]);
  assert.match([...issues].join(" "), /incomplete pointer/);
});

void test("rejects pointers into non-executable data and caches failures", async context => {
  const fixture = createNativeAotInvokeFixture();
  fixture.view.setInt32(fixture.fixupsRva, 0, true);
  const issues = new Set<string>();
  const reads = context.mock.method(fixture.image, "readData");
  const refs = new NativeAotCodeReferences(fixture.image, fixture.sections, issues);

  assert.equal(await refs.resolve(0), null);
  assert.equal(await refs.resolve(0), null);
  assert.equal(reads.mock.callCount(), 1);
  assert.match([...issues].join(" "), /file-backed executable code/);
});

void test("rejects short or missing pointer data", async () => {
  const fixture = createNativeAotInvokeFixture();
  const issues = new Set<string>();
  fixture.image.readData = async () => new DataView(new ArrayBuffer(3));

  assert.equal(await new NativeAotCodeReferences(fixture.image, fixture.sections, issues).resolve(0), null);
  assert.deepEqual([...issues], ["Common fixups code pointer is truncated or unreadable."]);
  fixture.image.readData = async () => null;
  assert.equal(await new NativeAotCodeReferences(fixture.image, fixture.sections, issues).resolve(0), null);
  assert.match([...issues].join(" "), /truncated or unreadable/);
});

void test("converts I/O failures to visible fixup warnings", async () => {
  const fixture = createNativeAotInvokeFixture();
  const issues = new Set<string>();
  fixture.image.readData = async () => { throw new Error("read error"); };

  assert.equal(await new NativeAotCodeReferences(fixture.image, fixture.sections, issues).resolve(0), null);
  assert.match([...issues].join(" "), /read error/);
  fixture.image.readData = async () => { throw "untyped error"; };
  assert.equal(await new NativeAotCodeReferences(fixture.image, fixture.sections, issues).resolve(0), null);
  assert.match([...issues].join(" "), /Common fixups read failed/);
});

void test("rejects a computed code address outside safe integer precision", async () => {
  const fixture = createNativeAotInvokeFixture();
  fixture.sections[1]!.rva = Number.MAX_SAFE_INTEGER;
  fixture.image.readData = async () => new DataView(Uint8Array.of(1, 0, 0, 0).buffer);
  fixture.image.isExecutableAddress = () => true;
  const issues = new Set<string>();

  assert.equal(await new NativeAotCodeReferences(fixture.image, fixture.sections, issues).resolve(0), null);
  assert.match([...issues].join(" "), /file-backed executable code/);
});

void test("accepts a table containing exactly one complete relative pointer", async () => {
  const fixture = createNativeAotInvokeFixture();
  fixture.sections[1]!.size = 4;
  const issues = new Set<string>();

  assert.equal(await new NativeAotCodeReferences(fixture.image, fixture.sections, issues).resolve(0),
    fixture.codeRvas[0]);
  assert.deepEqual([...issues], []);
});

void test("rejects fractional and end-of-table indices before reading pointer bytes", async context => {
  const fixture = createNativeAotInvokeFixture();
  const issues = new Set<string>();
  const reads = context.mock.method(fixture.image, "readData");
  const refs = new NativeAotCodeReferences(fixture.image, fixture.sections, issues);

  assert.equal(await refs.resolve(0.5), null);
  assert.equal(await refs.resolve(-1), null);
  assert.equal(await refs.resolve(2), null);
  assert.equal(reads.mock.callCount(), 0);
  assert.deepEqual([...issues], ["Common fixups code index is outside the table."]);
});

void test("rejects an oversized pointer read instead of accepting bytes from outside the slot", async () => {
  const fixture = createNativeAotInvokeFixture();
  const issues = new Set<string>();
  fixture.image.readData = async () => new DataView(fixture.bytes.buffer, fixture.fixupsRva, 5);

  assert.equal(await new NativeAotCodeReferences(fixture.image, fixture.sections, issues).resolve(0), null);
  assert.deepEqual([...issues], ["Common fixups code pointer is truncated or unreadable."]);
});

void test("rejects a fixup table whose size is outside safe integer precision", async context => {
  const fixture = createNativeAotInvokeFixture();
  fixture.sections[1]!.size = Number.MAX_SAFE_INTEGER + 1;
  const issues = new Set<string>();
  const reads = context.mock.method(fixture.image, "readData");

  assert.equal(await new NativeAotCodeReferences(fixture.image, fixture.sections, issues).resolve(0), null);
  assert.equal(reads.mock.callCount(), 0);
  assert.deepEqual([...issues], ["Common fixups code index is outside the table."]);
});
