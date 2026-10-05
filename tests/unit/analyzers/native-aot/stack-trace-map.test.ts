import assert from "node:assert/strict";
import test from "node:test";
import { NativeFormatReader } from "../../../../analyzers/native-aot/native-format-reader.js";
import { parseNativeAotStackTraceMap } from "../../../../analyzers/native-aot/stack-trace-map.js";
import { createNativeAotStackTraceFixture } from "../../../helpers/native-aot-stack-trace-fixture.js";

void test("NativeAOT stack-trace rows retain raw metadata context updates and signed code references", async () => {
  const fixture = createNativeAotStackTraceFixture();

  const map = await parseNativeAotStackTraceMap(fixture.image, [fixture.section]);

  assert.deepEqual(map, { entries: [
    { command: 27, methodRva: fixture.codeRvas[0], owningTypeToken: 0x01000020,
      nameOffset: 10, genericSignature: { signatureOffset: 20, argumentCollectionOffset: 30 } },
    { command: 4, methodRva: fixture.codeRvas[1], signatureOffset: 40 }
  ], warnings: [] });
});

void test("NativeAOT stack-trace parsing ignores absent maps and rejects duplicate sections", async () => {
  const fixture = createNativeAotStackTraceFixture();

  assert.equal(await parseNativeAotStackTraceMap(fixture.image, []), undefined);
  const map = await parseNativeAotStackTraceMap(fixture.image, [fixture.section, fixture.section]);
  assert.deepEqual(map?.entries, []);
  assert.match(map!.warnings.join(" "), /ambiguous/);
});

void test("NativeAOT stack-trace parsing retains readable rows when the declared count is excessive", async () => {
  const fixture = createNativeAotStackTraceFixture();
  // Four declared rows cannot fit: even minimum-size rows need 24 bytes including the count.
  fixture.view.setUint32(fixture.mapRva, 4, true);

  const map = await parseNativeAotStackTraceMap(fixture.image, [fixture.section]);

  assert.equal(map?.entries.length, 2);
  assert.ok(map!.warnings.includes("Stack-trace method table is truncated."));
});

void test("NativeAOT stack-trace parsing retains the valid prefix before a truncated later pointer", async () => {
  const fixture = createNativeAotStackTraceFixture();
  fixture.section.size -= 1;

  const map = await parseNativeAotStackTraceMap(fixture.image, [fixture.section]);

  assert.equal(map?.entries.length, 1);
  assert.match(map!.warnings.join(" "), /outside|bounds|truncated/);
});

void test("NativeAOT stack-trace parsing reports unknown command bits after a valid row", async () => {
  const fixture = createNativeAotStackTraceFixture();
  fixture.bytes[fixture.mapRva + 16] = 0x80;

  const map = await parseNativeAotStackTraceMap(fixture.image, [fixture.section]);

  assert.equal(map?.entries.length, 1);
  assert.match(map!.warnings.join(" "), /unknown command/);
});

void test("NativeAOT stack-trace parsing rejects data targets while retaining their metadata row", async () => {
  const fixture = createNativeAotStackTraceFixture();
  fixture.view.setInt32(fixture.mapRva + 12, 0, true);

  const map = await parseNativeAotStackTraceMap(fixture.image, [fixture.section]);

  assert.equal(map?.entries.length, 2);
  assert.equal(map!.entries[0]!.methodRva, null);
  assert.equal(map!.entries[1]!.methodRva, fixture.codeRvas[1]);
  assert.match(map!.warnings.join(" "), /file-backed executable/);
});

void test("NativeAOT stack-trace parsing reports trailing data and supports zero-row maps", async () => {
  const fixture = createNativeAotStackTraceFixture();
  fixture.view.setUint32(fixture.mapRva, 1, true);

  const trailing = await parseNativeAotStackTraceMap(fixture.image, [fixture.section]);
  fixture.view.setUint32(fixture.mapRva, 0, true);
  fixture.section.size = 4;
  const empty = await parseNativeAotStackTraceMap(fixture.image, [fixture.section]);

  assert.equal(trailing?.entries.length, 1);
  assert.match(trailing!.warnings.join(" "), /trailing/);
  assert.deepEqual(empty, { entries: [], warnings: [] });
});

void test("NativeAOT stack-trace parsing reports an unreadable count header", async () => {
  const fixture = createNativeAotStackTraceFixture();
  fixture.section.size = 3;

  const map = await parseNativeAotStackTraceMap(fixture.image, [fixture.section]);

  assert.deepEqual(map?.entries, []);
  assert.match(map!.warnings.join(" "), /outside|bounds|truncated/);
});

void test("NativeAOT stack-trace parsing normalizes a non-Error read failure", async context => {
  const fixture = createNativeAotStackTraceFixture();
  context.mock.method(NativeFormatReader.prototype, "uint32", () => { throw null; });

  const map = await parseNativeAotStackTraceMap(fixture.image, [fixture.section]);

  assert.deepEqual(map, { entries: [], warnings: ["Stack-trace table decoding failed."] });
});

void test("NativeAOT stack-trace parsing selects its map among unrelated metadata sections", async () => {
  const fixture = createNativeAotStackTraceFixture();

  const map = await parseNativeAotStackTraceMap(fixture.image,
    [{ type: 313, rva: 0, size: 4 }, fixture.section]);

  assert.equal(map?.entries.length, 2);
  assert.deepEqual(map?.warnings, []);
});
