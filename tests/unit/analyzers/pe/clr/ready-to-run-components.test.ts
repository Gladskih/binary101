import assert from "node:assert/strict";
import test from "node:test";
import { decodeReadyToRunComponents } from "../../../../../analyzers/pe/clr/ready-to-run-components.js";
import { createReadyToRunCompositeFixture } from "../../../../helpers/ready-to-run-composite-fixture.js";
import { MockFile } from "../../../../helpers/mock-file.js";
import { parseReadyToRun } from "../../../../../analyzers/pe/clr/ready-to-run.js";

const identityRva = (rva: number): number => rva;

void test("normal ReadyToRun analysis includes the decoded composite core headers", async () => {
  const fixture = createReadyToRunCompositeFixture();

  const data = await parseReadyToRun(fixture.reader, identityRva, fixture.clr, 0x8664);

  const decoded = data.sections[1]?.decoded;
  assert.ok(decoded?.kind === "components");
  assert.equal(decoded.entries[0]?.coreHeader?.sections[0]?.decoded?.kind, "methods");
  // The fixture's only runtime-function row is index 0; this component map deliberately uses 1.
  assert.deepEqual(data.issues,
    ["ReadyToRun component 1: ReadyToRun method map references a missing runtime-function index.",
      "ReadyToRun GC method root is outside the runtime-function table."]);
});

void test("component core size bounds reads and mixed directories cannot hide image-wide tables", async context => {
  const fixture = createReadyToRunCompositeFixture();
  fixture.component.coreHeaderSize = 4;
  const reads = context.mock.method(fixture.reader, "read");

  await decodeReadyToRunComponents(fixture.reader, identityRva, fixture.data, undefined);

  assert.equal(fixture.component.coreHeader, undefined);
  assert.equal(reads.mock.calls[0]?.arguments[1], 4);
  assert.match(fixture.data.issues.join(), /truncated/);
});

void test("truncated core directories retain valid sections without reading adjacent data", async () => {
  const fixture = createReadyToRunCompositeFixture();
  fixture.view.setUint32(fixture.coreHeaderRva + 4, 2, true);
  fixture.view.setUint32(fixture.coreHeaderRva + fixture.coreHeaderSize, 115, true);
  fixture.view.setUint32(fixture.coreHeaderRva + fixture.coreHeaderSize + 4,
    fixture.componentTableRva, true);
  fixture.view.setUint32(fixture.coreHeaderRva + fixture.coreHeaderSize + 8, 16, true);
  const reader = new MockFile(fixture.bytes);

  await decodeReadyToRunComponents(reader, identityRva, fixture.data, undefined);

  assert.equal(fixture.component.coreHeader?.sections.length, 1);
  assert.match(fixture.data.issues.join(), /section table is truncated/);
  assert.doesNotMatch(fixture.data.issues.join(), /image-wide/);
  fixture.component.coreHeaderSize = 32;
  fixture.data.issues.length = 0;
  await decodeReadyToRunComponents(reader, identityRva, fixture.data, undefined);
  assert.match(fixture.data.issues.join(), /image-wide/);
  assert.equal(fixture.component.coreHeader?.sections[1]?.decoded, undefined);
});

void test("decodes per-assembly method maps and validates indices against the image runtime table", async () => {
  const fixture = createReadyToRunCompositeFixture();

  await decodeReadyToRunComponents(fixture.reader, identityRva, fixture.data, 0x8664);

  assert.deepEqual(fixture.component.coreHeader, { flags: 32, sectionCount: 1, sections: [
      { type: 103, name: "MethodDefEntryPoints", rva: fixture.methodMapRva, size: 4,
      decoded: { kind: "methods", methods: [{ methodRid: 1, runtimeFunctionIndex: 1, fixupOffset: null }] } }
  ] });
  assert.match(fixture.data.issues.join(" "), /component 1.*missing runtime-function index/);
});

void test("shared component headers reuse parsing and preserve their assembly identity", async context => {
  const fixture = createReadyToRunCompositeFixture();
  const table = fixture.data.sections[1]!.decoded;
  assert.ok(table?.kind === "components");
  table.entries.push({ ...fixture.component });
  const reads = context.mock.method(fixture.reader, "read");

  await decodeReadyToRunComponents(fixture.reader, identityRva, fixture.data, undefined);

  assert.equal(table.entries[0]?.coreHeader, table.entries[1]?.coreHeader);
  assert.equal(reads.mock.callCount(), 3);
});

void test("truncated headers do not prevent later components from being decoded", async () => {
  const fixture = createReadyToRunCompositeFixture();
  const table = fixture.data.sections[1]!.decoded;
  assert.ok(table?.kind === "components");
  table.entries.unshift({ ...fixture.component, coreHeaderRva: fixture.bytes.length - 4 });

  await decodeReadyToRunComponents(fixture.reader, identityRva, fixture.data, undefined);

  assert.equal(table.entries[0]?.coreHeader, undefined);
  assert.ok(table.entries[1]?.coreHeader);
  assert.match(fixture.data.issues.join(" "), /component 1.*truncated/);
});

void test("image-wide ComponentAssemblies inside a component header warns without recursion", async () => {
  const fixture = createReadyToRunCompositeFixture();
  fixture.view.setUint32(fixture.coreHeaderRva + 8, 115, true);
  fixture.view.setUint32(fixture.coreHeaderRva + 12, fixture.componentTableRva, true);
  fixture.view.setUint32(fixture.coreHeaderRva + 16, 16, true);

  await decodeReadyToRunComponents(new MockFile(fixture.bytes), identityRva, fixture.data, undefined);

  assert.match(fixture.data.issues.join(" "), /image-wide/);
});

void test("conflicting sizes of a shared core header warn without losing consistent rows", async () => {
  const fixture = createReadyToRunCompositeFixture();
  const table = fixture.data.sections[1]!.decoded;
  assert.ok(table?.kind === "components");
  table.entries.push({ ...fixture.component, coreHeaderSize: 8 }, { ...fixture.component });

  await decodeReadyToRunComponents(fixture.reader, identityRva, fixture.data, undefined);

  assert.equal(table.entries[1]?.coreHeader, undefined);
  assert.equal(table.entries[0]?.coreHeader, table.entries[2]?.coreHeader);
  assert.match(fixture.data.issues.join(), /component 2.*conflicting sizes/);
});

void test("different component headers share decoding of identical section bytes", async context => {
  const fixture = createReadyToRunCompositeFixture();
  const duplicateCoreHeaderRva = fixture.coreHeaderRva + 0x40;
  fixture.bytes.copyWithin(duplicateCoreHeaderRva, fixture.coreHeaderRva,
    fixture.coreHeaderRva + fixture.coreHeaderSize);
  const reader = new MockFile(fixture.bytes);
  const reads = context.mock.method(reader, "read");
  const table = fixture.data.sections[1]!.decoded;
  assert.ok(table?.kind === "components");
  table.entries.push({ ...fixture.component, coreHeaderRva: duplicateCoreHeaderRva });

  await decodeReadyToRunComponents(reader, identityRva, fixture.data, undefined);

  assert.equal(table.entries[0]?.coreHeader?.sections[0]?.decoded,
    table.entries[1]?.coreHeader?.sections[0]?.decoded);
  assert.equal(reads.mock.callCount(), 5);
});

void test("absent, undecoded and ambiguous component directories do not guess an assembly", async () => {
  const fixture = createReadyToRunCompositeFixture();
  const directory = fixture.data.sections[1]!;
  fixture.data.sections.pop();

  await decodeReadyToRunComponents(fixture.reader, identityRva, fixture.data, undefined);
  const undecoded = { ...directory };
  delete undecoded.decoded;
  fixture.data.sections.push(undecoded);
  await decodeReadyToRunComponents(fixture.reader, identityRva, fixture.data, undefined);
  fixture.data.sections.push(directory);
  await decodeReadyToRunComponents(fixture.reader, identityRva, fixture.data, undefined);
  assert.equal(fixture.component.coreHeader, undefined);
  assert.match(fixture.data.issues.join(), /ambiguous/);
});

void test("invalid component ranges and non-Error I/O failures warn", async context => {
  const fixture = createReadyToRunCompositeFixture();
  fixture.component.coreHeaderRva = -1;

  await decodeReadyToRunComponents(fixture.reader, identityRva, fixture.data, undefined);
  assert.match(fixture.data.issues.join(), /invalid core header RVA range/);
  fixture.component.coreHeaderRva = fixture.coreHeaderRva;
  context.mock.method(fixture.reader, "read", async () => { throw "failure"; });
  await decodeReadyToRunComponents(fixture.reader, identityRva, fixture.data, undefined);
  assert.match(fixture.data.issues.join(), /decoding failed/);
});

void test("malformed nested components cannot alias the root table into a circular model", async () => {
  const fixture = createReadyToRunCompositeFixture();
  fixture.view.setUint32(fixture.coreHeaderRva + 8, 115, true);
  fixture.view.setUint32(fixture.coreHeaderRva + 12, fixture.componentTableRva, true);
  fixture.view.setUint32(fixture.coreHeaderRva + 16, 16, true);

  const parsed = await parseReadyToRun(new MockFile(fixture.bytes), identityRva, fixture.clr);

  const table = parsed.sections[1]!.decoded;
  assert.ok(table?.kind === "components");
  assert.equal(table.entries[0]?.coreHeader?.sections[0]?.decoded, undefined);
  assert.doesNotThrow(() => JSON.stringify(parsed));
  assert.match(parsed.issues.join(), /image-wide/);
});
