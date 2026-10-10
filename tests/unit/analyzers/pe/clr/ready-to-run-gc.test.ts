import assert from "node:assert/strict";
import { test } from "node:test";
import { decodeReadyToRunGc } from "../../../../../analyzers/pe/clr/ready-to-run-gc.js";
import { readyToRunGcFixture } from "../../../../helpers/ready-to-run-gc-fixture.js";
import { failManagedGcReadAt } from "../../../../helpers/managed-gc-container-fixture.js";

void test("binds method roots to cached R2R GC payloads", async () => {
  const source = readyToRunGcFixture();

  // IMAGE_FILE_MACHINE_AMD64 from PE/COFF.
  // https://learn.microsoft.com/windows/win32/debug/pe-format#machine-types
  await decodeReadyToRunGc(source.reader(), source.mapper, source.data, 0x8664);

  const decoded = source.data.sections[0]?.decoded;
  assert.ok(decoded?.kind === "gc-methods");
  assert.deepEqual(decoded.methods.map(method => method.startRva),
    [source.layout.methodRva, source.layout.nativeOnlyMethodRva]);
  assert.equal(decoded.methods[0]?.info.header.codeLength, source.layout.codeLength);
  assert.equal(decoded.methods[0]?.info, decoded.methods[1]?.info);
  assert.deepEqual(source.data.issues, []);
});

void test("reports partial runtime records and out-of-table managed roots", async () => {
  const source = readyToRunGcFixture();
  source.data.sections[0]!.size += 1; // One byte leaves an incomplete 12-byte RuntimeFunction.
  source.data.sections.push({ type: 109, name: "InstanceMethodEntryPoints", rva: 0, size: 0,
    decoded: { kind: "instance-methods", methods: [
      { signatureOffset: 0, runtimeFunctionIndex: Math.ceil(source.data.sections[0]!.size /
        source.layout.runtimeFunctionBytes), fixupOffset: null }] } });

  await decodeReadyToRunGc(source.reader(), source.mapper, source.data, 0x8664);

  assert.match(source.data.issues.join(), /truncated/);
  assert.match(source.data.issues.join(), /outside/);
});

void test("ignores other machines and preserves root-specific and I/O warnings", async () => {
  const source = readyToRunGcFixture();
  await decodeReadyToRunGc(source.reader(), source.mapper, source.data, undefined);
  // IMAGE_FILE_MACHINE_I386 is rejected by the AMD64-only unwind decoder.
  // https://learn.microsoft.com/windows/win32/debug/pe-format#machine-types
  await decodeReadyToRunGc(source.reader(), source.mapper, source.data, 0x14c);
  assert.equal(source.data.sections[0]?.decoded, undefined);
  source.bytes[source.layout.rootUnwindRva] = 3;
  await decodeReadyToRunGc(source.reader(), source.mapper, source.data, 0x8664);
  assert.match(source.data.issues.join(), /version/);
  const reader = source.reader();
  reader.read = async () => { throw new Error("read failed"); };
  await decodeReadyToRunGc(reader, source.mapper, source.data, 0x8664);
  assert.match(source.data.issues.join(), /read failed/);
  reader.read = async () => { throw "untyped read failed"; };
  await decodeReadyToRunGc(reader, source.mapper, source.data, 0x8664);
  assert.match(source.data.issues.join(), /untyped read failed/);
  source.data.sections = [];
  await decodeReadyToRunGc(reader, source.mapper, source.data, 0x8664);
});

void test("retains truncated table prefixes and skips unreadable GC headers", async () => {
  const source = readyToRunGcFixture();
  source.data.sections[0]!.size = source.bytes.length;
  source.bytes[source.layout.alignedGcInfoRva] = 0;

  await decodeReadyToRunGc(source.reader(), source.mapper, source.data, 0x8664);

  assert.match(source.data.issues.join(), /truncated/);
  assert.match(source.data.issues.join(), /zero code length/);
  source.data.sections = [source.data.sections[0]!];
  source.data.majorVersion = 10;
  await decodeReadyToRunGc(source.reader(), source.mapper, source.data, 0x8664);
  assert.deepEqual(source.data.sections[0]!.decoded, { kind: "gc-methods", methods: [] });
});

void test("reports untyped failures from individual unwind records", async () => {
  const source = readyToRunGcFixture();
  const reader = failManagedGcReadAt(source.reader(), source.layout.rootUnwindRva,
    "unwind read failed");

  await decodeReadyToRunGc(reader, source.mapper, source.data, 0x8664);

  assert.match(source.data.issues.join(), /unwind read failed/);
});
