import assert from "node:assert/strict";
import { test } from "node:test";
import { decodeCodeViewPayload } from "../../../../../analyzers/pe/debug/codeview-payload.js";
import { createC6CodeView } from "../../../../fixtures/pe-codeview-c6.js";
import { c6Module } from "../../../../fixtures/pe-codeview-c6.js";
import { legacyReader, legacyU16, legacyU32 } from "../../../../fixtures/pe-legacy-codeview.js";
import { readCodeViewC6Directories, readCodeViewC6Module } from "../../../../../analyzers/pe/debug/codeview-c6.js";
import { createExtraDebugPayloadSubject, identityRvaToOff } from "../../../../fixtures/pe-debug-extra-payloads.js";

void test("NB02 dispatch decodes the packed C6 directory and preserves names and source statistics", async () => {
  const subject = createExtraDebugPayloadSubject(createC6CodeView());
  const warnings: string[] = [];
  const result = await decodeCodeViewPayload(subject.file, subject.file.size, identityRvaToOff,
    0, subject.offset, subject.declaredSize, warning => warnings.push(warning));
  const data = result.legacyCodeView?.directories[0]?.subsections.map(section => section.data);

  assert.equal(result.legacyCodeView?.signature, "NB02");
  assert.deepEqual(data?.map(section => section?.kind), ["module", "publics", "types", "symbols", "libraries", "oldLines"]);
  assert.deepEqual(data?.[2], { kind: "types", encoding: "c6", records: [{ type: 93, name: "Alias" }] });
  assert.deepEqual(data?.[3], { kind: "symbols", encoding: "c6", records: [{ type: 0x84, name: "stack_name" }] });
  assert.deepEqual(warnings, []);
});

void test("NB02 directories use ten-byte entries and retain complete entries before truncation", async () => {
  const warnings: string[] = [];
  const bytes = createC6CodeView([]);
  const short = [...bytes, ...legacyU16(0x103), ...legacyU16(7), ...legacyU32(0x12345678), ...legacyU16(0xabcd), 0];
  short.splice(8, 2, ...legacyU16(2));
  const directories = await readCodeViewC6Directories(legacyReader(short, warnings), 8);

  assert.deepEqual(directories,
    [{ flags: 0, entries: [{ type: 0x103, module: 7, offset: 0x12345678, size: 0xabcd }] }]);
  assert.match(warnings[0]!, /past payload bounds/);
});

void test("NB02 directory empty, zero and truncated headers remain bounded", async () => {
  const warnings: string[] = [];
  await readCodeViewC6Directories(legacyReader(createC6CodeView([]), warnings), 8);
  assert.deepEqual(warnings, []);
  assert.deepEqual(await readCodeViewC6Directories(legacyReader(createC6CodeView([])), 8), [{ flags: 0, entries: [] }]);
  assert.deepEqual(await readCodeViewC6Directories(legacyReader([], warnings), 0), []);
  await assert.rejects(readCodeViewC6Directories(legacyReader([]), 8), /bounds/);
  assert.equal(warnings.length, 1);
  assert.match(warnings[0]!, /directory offset is zero/);
});

void test("C6 modules preserve additional segments following the name and zero means one segment", async () => {
  const many = await readCodeViewC6Module(legacyReader(c6Module("multi.obj", 3)));
  const zero = await readCodeViewC6Module(legacyReader(c6Module("single.obj", 0)));

  assert.deepEqual(many.segments, [{ segment: 1, offset: 16, size: 32 },
    { segment: 2, offset: 48, size: 64 }, { segment: 3, offset: 48, size: 64 }]);
  assert.equal(many.name, "multi.obj");
  assert.equal(zero.segments.length, 1);
});

void test("C6 modules diagnose reserved bytes and reject missing names or segments", async () => {
  const warnings: string[] = [];
  const reserved = c6Module();
  reserved[11] = 1;
  reserved.set(legacyU16(3), 6);
  reserved.set(legacyU16(9), 8);
  const module = await readCodeViewC6Module(legacyReader(reserved, warnings));
  await assert.rejects(readCodeViewC6Module(legacyReader(c6Module("multi", 2).slice(0, -1))), /segment array is truncated/);
  await assert.rejects(readCodeViewC6Module(legacyReader(c6Module().slice(0, 12))), /bounds/);
  assert.match(warnings[0]!, /reserved byte/);
  assert.equal(module.overlay, 3);
  assert.equal(module.library, 9);
  assert.equal(module.style, "CV");
});

void test("NB02 truncated directory keeps complete entries when six bytes of the next entry remain", async () => {
  const warnings: string[] = [];
  const bytes = [...createC6CodeView([]), ...new Array<number>(16).fill(0)];
  bytes.splice(8, 2, ...legacyU16(2));
  const directories = await readCodeViewC6Directories(legacyReader(bytes, warnings), 8);

  assert.equal(directories[0]!.entries.length, 1);
  assert.match(warnings[0]!, /past payload bounds/);
});
