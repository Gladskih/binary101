import assert from "node:assert/strict";
import { test } from "node:test";
import { decodeCodeViewPayload } from "../../../../../analyzers/pe/debug/codeview-payload.js";
import { createCv3CodeView, cv3Module32, cv3SourceLines, cv3Trailer } from "../../../../fixtures/pe-codeview-cv3.js";
import { legacyReader, legacyU32 } from "../../../../fixtures/pe-legacy-codeview.js";
import { createC6CodeView } from "../../../../fixtures/pe-codeview-c6.js";
import { createPeCodeViewOverlay } from "../../../../fixtures/pe-codeview-locations.js";
import { parsePe, isPeWindowsParseResult } from "../../../../../analyzers/pe/index.js";
import { createExtraDebugPayloadSubject, identityRvaToOff } from "../../../../fixtures/pe-debug-extra-payloads.js";
import { readCodeViewCv3Module32, readCodeViewCv3SourceLines, readCodeViewCv3Payload }
  from "../../../../../analyzers/pe/debug/codeview-cv3.js";

void test("NB00 in PE selects 32-bit contributions without changing the packed old directory", async () => {
  const subject = createExtraDebugPayloadSubject(createCv3CodeView());
  const warnings: string[] = [];
  const result = await decodeCodeViewPayload(subject.file, subject.file.size, identityRvaToOff,
    0, subject.offset, subject.declaredSize, warning => warnings.push(warning));
  const data = result.legacyCodeView?.directories[0]?.subsections.map(section => section.data);
  assert.equal(result.legacyCodeView?.signature, "NB00");
  assert.deepEqual(data?.[0], { kind: "module", name: "wide.obj", overlay: 3, library: 4, style: "CV",
    segments: [{ segment: 2, offset: 0x10020, size: 0x20040 }] });
  assert.deepEqual(data?.[2], { kind: "types", encoding: "c6", records: [{ type: 93, name: "Alias" }] });
  assert.deepEqual(data?.[3], { kind: "symbols", encoding: "c6", records: [{ type: 0x84, name: "stack_name" }] });
  assert.deepEqual(data?.[6], { kind: "oldLines", files: [{ name: "old.c",
    lines: [{ line: 7, offset: 16 }, { line: 9, offset: 24 }] }] });
  assert.deepEqual(warnings, []);
});

void test("CV3 trailers are excluded from logical bounds and broken lengths remain visible", async () => {
  const bytes = cv3Trailer(createCv3CodeView());
  const warnings: string[] = [];
  assert.equal((await readCodeViewCv3Payload(legacyReader(bytes, warnings))).size, bytes.length - 8);
  assert.deepEqual(warnings, []);
  bytes.set(legacyU32(16), bytes.length - 4);
  assert.equal((await readCodeViewCv3Payload(legacyReader(bytes, warnings))).size, bytes.length - 8);
  assert.match(warnings[0]!, /backward distance/);
  assert.equal((await readCodeViewCv3Payload(legacyReader(new Uint8Array(8)))).size, 8);
  assert.equal((await readCodeViewCv3Payload(legacyReader(createCv3CodeView()))).size, bytes.length - 8);
});

void test("CV3 PE contributions keep DWORD widths for additional segments and cSeg zero means one", async () => {
  const data = await readCodeViewCv3Module32(legacyReader(cv3Module32("wide.obj", 3)));
  assert.deepEqual(data.segments, [{ segment: 2, offset: 0x10020, size: 0x20040 },
    { segment: 3, offset: 0x30060, size: 0x40080 }, { segment: 4, offset: 0x30060, size: 0x40080 }]);
  assert.equal((await readCodeViewCv3Module32(legacyReader(cv3Module32("single.obj", 0)))).segments.length, 1);
  await assert.rejects(readCodeViewCv3Module32(legacyReader(cv3Module32("wide", 2).slice(0, -1))), /segments/);
  await assert.rejects(readCodeViewCv3Module32(legacyReader(cv3Module32().slice(0, 16))), /bounds/);
});

void test("CV3 reserved module bytes warn while preserving the name", async () => {
  const bytes = cv3Module32();
  bytes[15] = 1;
  const warnings: string[] = [];
  assert.equal((await readCodeViewCv3Module32(legacyReader(bytes, warnings))).name, "wide.obj");
  assert.match(warnings[0]!, /reserved/);
});

void test("CV3 source tables without segment fields keep consecutive file names and bounded WORD offsets", async () => {
  const data = await readCodeViewCv3SourceLines(legacyReader([...cv3SourceLines(), ...cv3SourceLines("second.c")]));
  assert.deepEqual(data.files.map(file => file.name), ["old.c", "second.c"]);
  assert.deepEqual(data.files[1]!.lines, [{ line: 7, offset: 16 }, { line: 9, offset: 24 }]);
  assert.deepEqual(await readCodeViewCv3SourceLines(legacyReader([])), { kind: "oldLines", files: [] });
  await assert.rejects(readCodeViewCv3SourceLines(legacyReader(cv3SourceLines().slice(0, -1))), /line pairs/);
  await assert.rejects(readCodeViewCv3SourceLines(legacyReader([5, 65])), /bounds/);
});

void test("NB00 anchored overlays reach the PE result and preserve source names", async () => {
  const pe = await parsePe(createPeCodeViewOverlay(cv3Trailer(createCv3CodeView())));
  assert.ok(pe && isPeWindowsParseResult(pe));
  const source = pe.debug?.codeViewSources?.[0];
  assert.equal(source?.kind, "overlay");
  assert.equal(source?.legacyCodeView.signature, "NB00");
  assert.equal(source?.legacyCodeView.directories[0]?.subsections[0]?.data?.kind, "module");
  assert.equal(pe.debug?.warning, undefined);
});

void test("NB02 also retains source tables with no segment field", async () => {
  const subject = createExtraDebugPayloadSubject(createC6CodeView([
    { type: 0x105, module: 1, data: Uint8Array.from(cv3SourceLines()) }
  ]));
  const result = await decodeCodeViewPayload(subject.file, subject.file.size, identityRvaToOff,
    0, subject.offset, subject.declaredSize, assert.fail);
  assert.deepEqual(result.legacyCodeView?.directories[0]?.subsections[0]?.data,
    { kind: "oldLines", files: [{ name: "old.c", lines: [{ line: 7, offset: 16 }, { line: 9, offset: 24 }] }] });
});

void test("NB00 invalid modules and out-of-bounds inventory warn without dropping neighboring records", async () => {
  const bytes = cv3Trailer(createCv3CodeView());
  bytes.set(legacyU32(bytes.length - 8), 14); // First subsection now points to the terminal trailer.
  const subject = createExtraDebugPayloadSubject(bytes);
  const warnings: string[] = [];
  const result = await decodeCodeViewPayload(subject.file, subject.file.size, identityRvaToOff,
    0, subject.offset, subject.declaredSize, warning => warnings.push(warning));
  assert.equal(result.legacyCodeView?.directories[0]?.subsections[0]?.data, undefined);
  assert.equal(result.legacyCodeView?.directories[0]?.subsections[1]?.data?.kind, "publics");
  assert.match(warnings[0]!, /outside payload bounds/);
});
