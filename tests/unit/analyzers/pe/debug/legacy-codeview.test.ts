import assert from "node:assert/strict";
import { test } from "node:test";
import { parseLegacyCodeView } from "../../../../../analyzers/pe/debug/legacy-codeview.js";
import { createLegacyCodeView, legacyModule, legacyU32 } from "../../../../fixtures/pe-legacy-codeview.js";
import { createExtraDebugPayloadSubject, identityRvaToOff } from "../../../../fixtures/pe-debug-extra-payloads.js";
import { createPeWithEmbeddedCodeView } from "../../../../fixtures/pe-codeview-embedded-symbols.js";
import { parsePeHeaders } from "../../../../../analyzers/pe/core/index.js";
import { parseDebugDirectory } from "../../../../../analyzers/pe/debug/directory.js";
import { codeViewStoredTypeText } from "../../../../fixtures/pe-codeview-type-strings.js";

const parse = async (bytes: Uint8Array, declaredSize = bytes.length) => {
  const subject = createExtraDebugPayloadSubject(bytes, declaredSize);
  const warnings: string[] = [];
  const parsed = await parseLegacyCodeView(subject.file, subject.file.size, identityRvaToOff,
    0, subject.offset, declaredSize, warning => warnings.push(warning));
  return { parsed, warnings };
};

void test("legacy CodeView decodes supported directory subsections and retains unknown inventory", async () => {
  const { parsed, warnings } = await parse(createLegacyCodeView());

  assert.equal(parsed?.signature, "NB09");
  assert.deepEqual(parsed?.directories[0]?.subsections.map(section => section.data?.kind),
    ["module", "libraries", "symbols", "source"]);
  assert.deepEqual(warnings, []);
});

void test("PE debug-directory integration retains embedded symbols, base names and discard source metadata", async () => {
  const file = createPeWithEmbeddedCodeView();
  const core = await parsePeHeaders(file);
  assert.ok(core);
  const parsed = await parseDebugDirectory(file, core.dataDirs, core.rvaToOff, core.coff.Machine);
  const sections = parsed.entries[0]!.legacyCodeView!.directories[0]!.subsections;
  const symbols = sections[0]!.data;
  const types = sections[1]!.data;
  assert.equal(symbols?.kind, "symbols");
  assert.equal(types?.kind, "types");

  assert.equal(parsed.warning, null);
  assert.equal(symbols.records.length, 3);
  assert.equal(symbols.records[0]!.children?.length, 102);
  assert.deepEqual(symbols.records[0]!.discarded, { reason: 2, fileId: 7, line: 42 });
  assert.deepEqual(symbols.records[2]!.children, [{ type: 0x110e, name: "thisAlias" }]);
  assert.deepEqual(codeViewStoredTypeText(types.records), [{ type: 0x20c, symbols: [{ type: 0x110e, name: "referenced" }] },
    { type: 2, strings: ["BaseType"] }, { type: 0x1002, symbols: [{ type: 0x110d, name: "basedValue" }] }]);
});

void test("legacy CodeView keeps valid subsections when another is malformed or unknown", async () => {
  const bytes = createLegacyCodeView([{ type: 0x120, module: 1, data: new Uint8Array(1) },
    { type: 0x999, module: 0xffff, data: new Uint8Array(0) },
    { type: 0x120, module: 2, data: legacyModule("good.obj") }]);
  bytes.set(legacyU32(0xffffffff), 40);
  const { parsed, warnings } = await parse(bytes);

  assert.equal(parsed?.directories[0]?.subsections.length, 3);
  assert.equal(parsed?.directories[0]?.subsections[0]?.data, undefined);
  assert.equal(parsed?.directories[0]?.subsections[1]?.data, undefined);
  assert.equal(parsed?.directories[0]?.subsections[2]?.data?.kind, "module");
  assert.match(warnings.join(" | "), /bounds/);
});

void test("legacy CodeView rejects unknown signatures, short headers and unmapped data", async () => {
  const unknown = await parse(createLegacyCodeView([], "NB03"));
  const short = await parse(Uint8Array.of(78, 66, 48));
  const empty = await parse(new Uint8Array());

  assert.equal(unknown.parsed, null);
  assert.match(unknown.warnings.join(" | "), /Unsupported legacy/);
  assert.equal(short.parsed, null);
  assert.match(short.warnings.join(" | "), /bounds/);
  assert.equal(empty.parsed, null);
});

void test("legacy CodeView retains an available header when SizeOfData is truncated", async () => {
  const { parsed, warnings } = await parse(createLegacyCodeView([]), 1000);

  assert.equal(parsed?.signature, "NB09");
  assert.match(warnings.join(" | "), /shorter than.*SizeOfData/);
});

void test("legacy CodeView dispatches global type origins and retains unknown but bounded subsections", async () => {
  const { parsed, warnings } = await parse(createLegacyCodeView([
    { type: 0x12b, module: 0xffff, data: Uint8Array.from([1, 0, 0, 0,
      ...legacyU32(1), ...legacyU32(0), 2, 0, 0x77, 0x77]) },
    { type: 0x999, module: 0xffff, data: new Uint8Array() }
  ]));

  assert.deepEqual(parsed?.directories[0]?.subsections[0]?.data,
    { kind: "types", records: [{ type: 0x7777, index: 0x1000 }] });
  assert.equal(parsed?.directories[0]?.subsections[1]?.data, undefined);
  assert.deepEqual(warnings, []);
});

void test("legacy CodeView decodes identical subsection references once", async () => {
  const bytes = createLegacyCodeView([{ type: 0x120, module: 1, data: legacyModule() },
    { type: 0x120, module: 2, data: legacyModule() }]);
  bytes.set(bytes.subarray(28, 36), 40);
  const { parsed, warnings } = await parse(bytes);
  const sections = parsed?.directories[0]?.subsections;

  assert.equal(sections?.[0]?.data, sections?.[1]?.data);
  assert.ok(sections?.[0]?.data);
  assert.deepEqual(warnings, []);
});

void test("legacy CodeView does not rescan a damaged subsection referenced by multiple modules", async () => {
  const bytes = createLegacyCodeView([{ type: 0x120, module: 1, data: new Uint8Array(1) },
    { type: 0x120, module: 2, data: new Uint8Array(1) }]);
  bytes.set(bytes.subarray(28, 36), 40);
  const { parsed, warnings } = await parse(bytes);

  assert.equal(parsed?.directories[0]?.subsections.length, 2);
  assert.equal(parsed?.directories[0]?.subsections[0]?.data, undefined);
  assert.equal(parsed?.directories[0]?.subsections[1]?.data, undefined);
  assert.equal(warnings.length, 1);
});
