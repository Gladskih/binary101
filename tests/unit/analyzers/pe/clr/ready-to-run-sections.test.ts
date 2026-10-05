import assert from "node:assert/strict";
import { test } from "node:test";
import { decodeReadyToRunSections } from "../../../../../analyzers/pe/clr/ready-to-run-sections.js";
import type { PeClrReadyToRunSection } from "../../../../../analyzers/pe/clr/ready-to-run-types.js";
import { MockFile } from "../../../../helpers/mock-file.js";
import { createReadyToRunImportFixture } from "../../../../helpers/ready-to-run-import-fixture.js";

const section = (type: number, size: number): PeClrReadyToRunSection =>
  ({ type, name: `Section${type}`, rva: 0, size });

void test("reads counted compiler text and NUL-terminated owner names", async () => {
  const sections = [section(100, 3), section(116, 3)];
  const issues: string[] = [];

  await decodeReadyToRunSections(new MockFile(Uint8Array.of(65, 66, 0)), rva => rva,
    sections, 8, issues);

  assert.deepEqual(sections.map(item => item.decoded),
    [{ kind: "text", text: "AB" }, { kind: "text", text: "AB" }]);
  assert.deepEqual(issues, []);
});

void test("accepts unterminated compiler text but warns for an unterminated owner name", async () => {
  const sections = [section(100, 2), section(116, 2)];
  const issues: string[] = [];

  await decodeReadyToRunSections(new MockFile(Uint8Array.of(65, 66)), rva => rva,
    sections, undefined, issues);

  assert.deepEqual(sections[0]?.decoded, { kind: "text", text: "AB" });
  assert.deepEqual(issues, ["OwnerCompositeExecutable has no NUL terminator."]);
});

void test("decodes component directories and hot/cold runtime-function pairs", async () => {
  const bytes = new Uint8Array(17);
  const view = new DataView(bytes.buffer);
  [11, 22, 33, 44].forEach((value, index) => view.setUint32(index * 4, value, true));
  const sections = [section(115, bytes.length), section(120, 9)];
  const issues: string[] = [];

  await decodeReadyToRunSections(new MockFile(bytes), rva => rva, sections, 8, issues);

  assert.deepEqual(sections[0]?.decoded, { kind: "components", entries: [
    { clrRva: 11, clrSize: 22, coreHeaderRva: 33, coreHeaderSize: 44 }
  ] });
  assert.deepEqual(sections[1]?.decoded, { kind: "hot-cold", entries: [
    { coldRuntimeFunction: 11, hotRuntimeFunction: 22 }
  ] });
  assert.equal(issues.length, 2);
});

void test("decodes imports and MethodDef entry points, leaving unknown section types intact", async () => {
  const fixture = createReadyToRunImportFixture();
  const imports = section(101, 20);
  const methods = section(103, 4);
  const unknown = section(999, 3);
  const issues: string[] = [];
  await decodeReadyToRunSections(fixture.reader, rva => rva, [imports, unknown], 8, issues);
  await decodeReadyToRunSections(new MockFile(Uint8Array.of(8, 1, 0, 12)), rva => rva,
    [methods], 8, issues);

  assert.equal(imports.decoded?.kind, "imports");
  assert.deepEqual(methods.decoded, { kind: "methods", methods: [
    { methodRid: 1, runtimeFunctionIndex: 3, fixupOffset: null }
  ] });
  assert.equal(unknown.decoded, undefined);
  assert.deepEqual(issues, []);
});

void test("reports section truncation and invalid UTF-8 without throwing", async () => {
  const sections = [section(100, 3), section(103, 2)];
  const issues: string[] = [];

  await decodeReadyToRunSections(new MockFile(Uint8Array.of(0xff)), rva => rva,
    sections, 8, issues);

  assert.equal(sections[0]?.decoded, undefined);
  assert.match(issues.join(" "), /truncated/);
  assert.match(issues.join(" "), /Section100/);
  assert.match(issues.join(" "), /Section103/);
});

void test("decodes exact component and hot/cold boundaries without spurious warnings", async () => {
  const sections = [section(115, 16), section(120, 8)];
  const issues: string[] = [];
  const file = new MockFile(Uint8Array.of(11, 0, 0, 0, 22, 0, 0, 0, 33, 0, 0, 0, 44, 0, 0, 0));

  await decodeReadyToRunSections(file, rva => rva, sections, 8, issues);

  assert.deepEqual(sections[0]?.decoded, { kind: "components", entries: [
    { clrRva: 11, clrSize: 22, coreHeaderRva: 33, coreHeaderSize: 44 }
  ] });
  assert.deepEqual(sections[1]?.decoded, { kind: "hot-cold", entries: [
    { coldRuntimeFunction: 11, hotRuntimeFunction: 22 }
  ] });
  assert.deepEqual(issues, []);
});

void test("reports file-read failures and continues with later sections", async () => {
  const file = new MockFile(Uint8Array.of(65, 66));
  const issues: string[] = [];
  file.read = async () => { throw new Error("I/O failed"); };

  await decodeReadyToRunSections(file, rva => rva, [section(100, 2)], 8, issues);

  assert.match(issues.join(), /Section100.*I\/O failed/);
});
