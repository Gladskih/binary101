import assert from "node:assert/strict";
import { test } from "node:test";
import * as iced from "iced-x86-disasm";
import { createAmd64PrologValidator }
  from "../../../../../../analyzers/pe/exception/amd64/prolog-validation.js";
import { Amd64PrologChecker } from "../../../../../../analyzers/pe/exception/amd64/prolog-check.js";
import { prologCodeImage, prologDescription, distinctConstantPrologs, feedPrologDescriptions }
  from "../../../../../helpers/pe-prolog-fixture.js";

void test("reuses one decode for byte-identical prologs sharing a description", async context => {
  const image = prologCodeImage([0x50, 0x90], 2);
  const check = context.mock.method(Amd64PrologChecker.prototype, "check");
  const validator = await createAmd64PrologValidator(image.file, rva => rva, image.owners);
  context.after(validator.free);
  await validator.observe(1, prologDescription([{ opcode: "ALLOC_SMALL", codeOffset: 1, size: 8 }], 1));
  await validator.finish();

  assert.deepEqual(validator.report, { matchedCount: 2, unverifiedCounts: {}, findings: [] });
  assert.equal(check.mock.calls.filter(call => call.arguments[0].length > 0).length, 1);
  assert.equal(check.mock.calls.filter(call => call.arguments[0].length === 0).length, 1);
});

void test("retains range and unwind provenance for every mismatch", async context => {
  const image = prologCodeImage([0x50, 0x90], 2);
  const validator = await createAmd64PrologValidator(image.file, rva => rva, image.owners);
  context.after(validator.free);
  await validator.observe(1, prologDescription([], 1));
  await validator.finish();

  assert.deepEqual(validator.report.findings.map(finding => [finding.beginRva,
    finding.endRva, finding.unwindInfoRva]), image.owners.get(1)!.map(range => [range.begin, range.end, 1]));
  assert.equal(validator.report.matchedCount, 0);
});

void test("reports a prolog extending past its declared function without reading code", async context => {
  const image = prologCodeImage([0x90]);
  const read = context.mock.method(image.file, "read");
  const validator = await createAmd64PrologValidator(image.file, rva => rva, image.owners);
  context.after(validator.free);
  await validator.observe(1, prologDescription([], 2));
  await validator.finish();

  assert.equal(validator.report.findings[0]?.issues[0]?.code, "prolog-size");
  assert.equal(read.mock.callCount(), 0);
});

void test("reports an unreadable mapped prefix and preserves incomplete coverage", async context => {
  const image = prologCodeImage([0x48, 0x83, 0xec, 0x28]);
  const validator = await createAmd64PrologValidator(image.file, () => null, image.owners);
  context.after(validator.free);
  await validator.observe(1, prologDescription([], 4));
  await validator.finish();

  assert.deepEqual(validator.report.unverifiedCounts, { "unreadable-code": 1 });
  assert.deepEqual(validator.report.findings, []);
});

void test("keeps I/O failure local to the code check", async context => {
  const image = prologCodeImage([0x90]);
  context.mock.method(image.file, "read", async () => { throw new Error("Read failure"); });
  const validator = await createAmd64PrologValidator(image.file, rva => rva, image.owners);
  context.after(validator.free);
  await validator.observe(1, prologDescription([], 1));
  await validator.finish();

  assert.deepEqual(validator.report.unverifiedCounts, { "code-read-failed": 1 });
});

void test("counts unsupported metadata without reading or decoding code", async context => {
  const image = prologCodeImage([0x90]);
  const read = context.mock.method(image.file, "read");
  const validator = await createAmd64PrologValidator(image.file, rva => rva, image.owners);
  context.after(validator.free);
  await validator.observe(1, prologDescription([], 1, { version: 3 }));
  await validator.observe(2, prologDescription([], 1));
  await validator.finish();

  assert.deepEqual(validator.report.unverifiedCounts, { "unwind-version": 1 });
  assert.equal(read.mock.callCount(), 0);
});

void test("propagates a disassembler load failure to the parser's visible fallback", async () => {
  const image = prologCodeImage([0x90]);
  await assert.rejects(createAmd64PrologValidator(image.file, rva => rva, image.owners,
    async () => { throw new Error("Unavailable WASM"); }), /Unavailable WASM/);
});

void test("can use an injected module without changing results", async context => {
  const image = prologCodeImage([0x90]);
  const validator = await createAmd64PrologValidator(image.file, rva => rva, image.owners,
    async () => iced);
  context.after(validator.free);
  await validator.observe(1, prologDescription([], 1));
  await validator.finish();
  assert.equal(validator.report.matchedCount, 1);
});

void test("does not reuse a range-dependent incomplete result for a longer function", async context => {
  const image = prologCodeImage([0x50, 0x90], 2);
  image.owners.get(1)![0]!.end--;
  const validator = await createAmd64PrologValidator(image.file, rva => rva, image.owners);
  context.after(validator.free);
  await validator.observe(1, prologDescription([], 1));
  await validator.finish();
  assert.equal(validator.report.findings.length, 1);
  assert.deepEqual(validator.report.unverifiedCounts, { "function-end": 1 });
});

void test("flushes bounded metadata batches before the final finish call", async context => {
  const image = prologCodeImage([0x90, 0x90], 32);
  const owners = new Map(image.owners.get(1)!.map((range, index) => [index + 1, [range]]));
  const validator = await createAmd64PrologValidator(image.file, rva => rva, owners);
  context.after(validator.free);
  // 32 descriptions * (255 single-slot operations + one header) reaches the
  // measured 8192-record scheduling budget; this is not a format-size limit.
  const description = prologDescription(Array.from({ length: 255 }, () =>
    ({ opcode: "PUSH_NONVOL", codeOffset: 1, register: 0 })), 1);
  await feedPrologDescriptions(validator.observe, owners.keys(), description);
  assert.equal(validator.report.findings.length, 32);
  await validator.finish();
  assert.equal(validator.report.findings.length, 32);
});

void test("continues checking every function after exhausting the bounded memo", async context => {
  const image = distinctConstantPrologs(5000);
  const validator = await createAmd64PrologValidator(image.file, rva => rva, image.owners);
  context.after(validator.free);
  await validator.observe(1, prologDescription([], 5));
  await validator.finish();
  assert.deepEqual(validator.report, { matchedCount: 5000, findings: [], unverifiedCounts: {} });
});
