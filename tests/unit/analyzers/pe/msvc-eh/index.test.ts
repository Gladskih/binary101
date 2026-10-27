import assert from "node:assert/strict";
import { test } from "node:test";
import { analyzeMsvcEh } from "../../../../../analyzers/pe/msvc-eh/index.js";
import { createEhFixture, addFh3, addFh4 } from "../../../../fixtures/pe-msvc-eh.js";

void test("EH analysis requires linked personality, complete tables and function IP evidence", async () => {
  const subject = createEhFixture();
  const { infoRva } = addFh3(subject);
  const fixture = subject.builder.build();
  const parsed = await analyzeMsvcEh(fixture.file, fixture.core, subject.exception, subject.imports, []);
  assert.equal(parsed?.records[0]?.functionInfo?.rva, infoRva);
  assert.deepEqual(parsed?.records[0]?.functionRvas, [subject.beginRva]);
  assert.equal(parsed?.records[0]?.personality, "__CxxFrameHandler3");
  assert.deepEqual(parsed?.warnings, []);
});

void test("FH4 bytes are never recognized from plausible metadata alone", async () => {
  const subject = createEhFixture();
  addFh4(subject);
  subject.imports.entries[0]!.functions[0]!.name = "unrelated";
  const fixture = subject.builder.build();
  assert.equal(await analyzeMsvcEh(fixture.file, fixture.core, subject.exception, subject.imports, []), null);
});

void test("confirmed personality with malformed data yields a warning, not a claimed object", async () => {
  const subject = createEhFixture();
  addFh3(subject);
  subject.builder.patchUint32(subject.dataRva, 0, 0xffffffff);
  const fixture = subject.builder.build();
  const parsed = await analyzeMsvcEh(fixture.file, fixture.core, subject.exception, subject.imports, []);
  assert.deepEqual(parsed?.records, []);
  assert.match(parsed?.warnings[0] ?? "", /metadata.*not validated/i);
});

void test("a proven FH3 object survives a contradictory runtime-function link with a diagnostic", async () => {
  const subject = createEhFixture();
  const { infoRva, ipMapRva } = addFh3(subject);
  subject.builder.patchUint32(ipMapRva, 0, subject.handlerRva);
  const fixture = subject.builder.build();
  const parsed = await analyzeMsvcEh(fixture.file, fixture.core, subject.exception, subject.imports, []);
  assert.equal(parsed?.records[0]?.functionInfo?.rva, infoRva);
  assert.match(parsed?.warnings[0] ?? "", /IP-to-state.*runtime/i);
});

void test("shared FH4 metadata is resolved separately for each runtime-function base", async () => {
  const subject = createEhFixture();
  addFh4(subject);
  subject.exception.functionCount = 2;
  subject.exception.beginRvas.push(subject.catchRva);
  subject.exception.rangeLengths.push(16);
  subject.exception.languageHandlers[0]!.functionRanges.push({ begin: subject.catchRva, end: subject.catchRva + 16 });
  const fixture = subject.builder.build();
  const parsed = await analyzeMsvcEh(fixture.file, fixture.core, subject.exception, subject.imports, []);
  assert.equal(parsed?.records.length, 2);
  assert.deepEqual(parsed?.records[1]?.functionInfo?.tryBlocks[0]?.handlers[0]?.continuationRvas,
    [subject.catchRva + 8]);
});

void test("unnamed FH3 requires both a substantive graph and independent runtime coverage", async () => {
  const subject = createEhFixture();
  addFh3(subject);
  const fixture = subject.builder.build();
  const parsed = await analyzeMsvcEh(fixture.file, fixture.core, subject.exception, null, []);
  assert.equal(parsed?.records[0]?.functionInfo?.version, 3);
  assert.equal(parsed?.records[0]?.personality, undefined);
  assert.match(parsed?.records[0]?.evidence ?? "", /identity unresolved/);
  assert.equal(await analyzeMsvcEh(fixture.file, fixture.core,
    { ...subject.exception, issues: ["truncated"] }, null, []), null);
});

void test("named handler with no valid owner yields diagnostics without a record", async () => {
  const subject = createEhFixture();
  addFh3(subject);
  subject.exception.languageHandlers[0]!.functionRanges = [];
  const fixture = subject.builder.build();
  const parsed = await analyzeMsvcEh(fixture.file, fixture.core, subject.exception, subject.imports, []);
  assert.deepEqual(parsed?.records, []);
  assert.equal(parsed?.warnings.length, 1);
});

void test("truncated handler data is not a parsed FuncInfo", async () => {
  const subject = createEhFixture();
  addFh3(subject);
  subject.exception.languageHandlers[0]!.dataRva = 0xffffffff;
  const fixture = subject.builder.build();
  assert.equal((await analyzeMsvcEh(fixture.file, fixture.core, subject.exception,
    subject.imports, []))?.records.length, 0);
});

void test("SEH object survives an owner-range contradiction with an explicit warning", async () => {
  const subject = createEhFixture();
  subject.imports.entries[0]!.functions[0]!.name = "__C_specific_handler";
  const scopes = subject.builder.allocateData(20);
  subject.builder.patchUint32(scopes, 0, 1);
  subject.builder.patchUint32(scopes, 4, subject.handlerRva);
  subject.builder.patchUint32(scopes, 8, subject.handlerRva + 4);
  subject.builder.patchUint32(scopes, 12, 1);
  subject.builder.patchUint32(scopes, 16, subject.catchRva);
  subject.exception.languageHandlers[0]!.dataRva = scopes;
  const fixture = subject.builder.build();
  const parsed = await analyzeMsvcEh(fixture.file, fixture.core, subject.exception, subject.imports, []);
  assert.equal(parsed?.records[0]?.scopeTableRva, scopes);
  assert.match(parsed?.warnings[0] ?? "", /SEH scope table.*outside/);
});

void test("SEH personality with an invalid scope count produces no scope object", async () => {
  const subject = createEhFixture();
  subject.imports.entries[0]!.functions[0]!.name = "__C_specific_handler";
  const fixture = subject.builder.build();
  assert.equal((await analyzeMsvcEh(fixture.file, fixture.core, subject.exception,
    subject.imports, []))?.records.length, 0);
});

void test("hybrid architectures and mismatched optional headers are not reinterpreted", async () => {
  const subject = createEhFixture();
  addFh3(subject);
  const fixture = subject.builder.build();
  fixture.core.coff.Machine = 0xa641;
  assert.equal(await analyzeMsvcEh(fixture.file, fixture.core, subject.exception, subject.imports, []), null);
  fixture.core.coff.Machine = 0x14c;
  assert.equal(await analyzeMsvcEh(fixture.file, fixture.core, subject.exception, subject.imports, []), null);
  fixture.core.opt = { ...fixture.core.opt, Magic: 0x10b, BaseOfData: 0x2000 };
  assert.equal(await analyzeMsvcEh(fixture.file, fixture.core, null, null, []), null);
});

for (const [machine, magic, expected] of [
  [0xaa64, 0x20b, true], [0x1c4, 0x10b, true], [0x8664, 0x10b, false], [0x1c4, 0x20b, false]
] as const) {
  void test(`linked FH3 metadata respects machine ${machine} and header magic ${magic}`, async () => {
    const subject = createEhFixture();
    addFh3(subject);
    const fixture = subject.builder.build();
    fixture.core.coff.Machine = machine;
    fixture.core.opt = { ...fixture.core.opt, Magic: magic, BaseOfData: 0x2000 };
    const parsed = await analyzeMsvcEh(fixture.file, fixture.core, subject.exception, null, []);
    assert.equal((parsed?.records.length ?? 0) > 0, expected);
  });
}

for (const [action, expected] of [[0, false], [0x1010, true]] as const) {
  void test(`unnamed cleanup-only FH3 requires a substantive action ${action}`, async () => {
    const subject = createEhFixture();
    const { infoRva, unwindRva } = addFh3(subject);
    subject.builder.patchUint32(infoRva, 12, 0);
    subject.builder.patchUint32(infoRva, 16, 0);
    subject.builder.patchUint32(unwindRva, 4, action);
    const fixture = subject.builder.build();
    const parsed = await analyzeMsvcEh(fixture.file, fixture.core, subject.exception, null, []);
    assert.equal((parsed?.records.length ?? 0) > 0, expected);
  });
}

void test("one executable owner cannot hide an invalid owner of shared metadata", async () => {
  const subject = createEhFixture();
  addFh3(subject);
  subject.exception.languageHandlers[0]!.functionRanges.push({ begin: 0x2000, end: 0x2010 });
  const fixture = subject.builder.build();
  const parsed = await analyzeMsvcEh(fixture.file, fixture.core, subject.exception, subject.imports, []);
  assert.deepEqual(parsed?.records, []);
});

void test("SEH boundary labels belong to any matching owner without spurious diagnostics", async () => {
  const subject = createEhFixture();
  subject.imports.entries[0]!.functions[0]!.name = "__C_specific_handler";
  const scopes = subject.builder.allocateData(20);
  subject.builder.patchUint32(scopes, 0, 1);
  subject.builder.patchUint32(scopes, 4, subject.beginRva);
  subject.builder.patchUint32(scopes, 8, subject.beginRva + 16);
  subject.builder.patchUint32(scopes, 12, 1);
  subject.builder.patchUint32(scopes, 16, subject.catchRva);
  subject.exception.languageHandlers[0]!.dataRva = scopes;
  subject.exception.languageHandlers[0]!.functionRanges.push({ begin: subject.catchRva, end: subject.catchRva + 16 });
  const fixture = subject.builder.build();
  const parsed = await analyzeMsvcEh(fixture.file, fixture.core, subject.exception, subject.imports, []);
  assert.equal(parsed?.records[0]?.scopeTableRva, scopes);
  assert.deepEqual(parsed?.warnings, []);
});

void test("FH4 never uses a CHAININFO secondary start as its relative-address base", async () => {
  const subject = createEhFixture();
  addFh4(subject);
  subject.exception.languageHandlers[0]!.functionRanges = [
    { begin: subject.beginRva, end: subject.beginRva + 16, sourceUnwindInfoRva: subject.unwindInfoRva },
    { begin: subject.catchRva, end: subject.catchRva + 16, sourceUnwindInfoRva: subject.unwindInfoRva + 16 }
  ];
  const fixture = subject.builder.build();
  const analysis = await analyzeMsvcEh(fixture.file, fixture.core, subject.exception, subject.imports, []);
  assert.equal(analysis?.records.length, 1);
  assert.deepEqual(analysis?.records[0]?.functionRvas, [subject.beginRva]);
});
