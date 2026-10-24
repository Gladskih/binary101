import assert from "node:assert/strict";
import { test } from "node:test";
import { parseExceptionDebugInfo } from "../../../../../analyzers/pe/debug/exception.js";
import { MockFile } from "../../../../helpers/mock-file.js";
import { parseDebugDirectory } from "../../../../../analyzers/pe/debug/directory.js";

const exception = { name: "EXCEPTION", rva: 0x1000, size: 24 };
const mapRva = (rva: number): number | null => {
  if (rva >= 0x1000 && rva < 0x1018) return 0x40 + rva - 0x1000;
  if (rva >= 0x2000 && rva < 0x2010) return 0x80 + rva - 0x2000;
  if (rva >= 0x3000 && rva < 0x3004) return 0x90 + rva - 0x3000;
  if (rva >= 0x4000 && rva < 0x4018) return 0x20 + rva - 0x4000;
  return null;
};
const subject = () => {
  const bytes = new Uint8Array(0xa0);
  const view = new DataView(bytes.buffer);
  // RUNTIME_FUNCTION_INDIRECT is bit 0; 0x100d references the row at 0x100c.
  // https://github.com/microsoft/win32metadata/blob/main/generation/WinSDK/RecompiledIdlHeaders/um/winnt.h
  const rows = [0x2000, 0x2004, 0x100d, 0x2004, 0x2008, 0x3000];
  rows.forEach((value, index) => {
    view.setUint32(0x20 + index * 4, value, true);
    view.setUint32(0x40 + index * 4, value, true);
  });
  bytes[0x90] = 1; // Valid version-1 UNWIND_INFO, no codes or handler.
  return new MockFile(bytes);
};

void test("raw-only .pdata copy uses the actual image-table origin for indirect unwind references", async () => {
  const file = subject();
  const warnings: string[] = [];
  const parsed = await parseExceptionDebugInfo(file, mapRva, 0, 0x20, 24,
    0x8664, warning => warnings.push(warning), exception);

  assert.equal(parsed?.functionCount, 2);
  assert.equal(parsed?.invalidEntryCount, 0);
  assert.equal(parsed?.uniqueUnwindInfoCount, 1);
  assert.deepEqual(parsed?.issues, []);
  assert.deepEqual(warnings, []);
});

void test("raw-only AMD64 .pdata decodes direct image RVAs without a table-origin RVA", async () => {
  const bytes = subject().data.slice();
  new DataView(bytes.buffer).setUint32(0x28, 0x3000, true);
  const warnings: string[] = [];
  const parsed = await parseExceptionDebugInfo(new MockFile(bytes), mapRva, 0, 0x20, 24,
    0x8664, warning => warnings.push(warning));

  assert.equal(parsed?.functionCount, 2);
  assert.equal(parsed?.invalidEntryCount, 0);
  assert.equal(parsed?.uniqueUnwindInfoCount, 1);
  assert.deepEqual(parsed?.issues, []);
  assert.deepEqual(warnings, []);
});

void test("raw-only AMD64 .pdata retains direct rows and diagnoses unverifiable indirect references", async () => {
  const warnings: string[] = [];
  const parsed = await parseExceptionDebugInfo(subject(), mapRva, 0, 0x20, 24,
    0x8664, warning => warnings.push(warning));

  assert.equal(parsed?.functionCount, 2);
  assert.equal(parsed?.invalidEntryCount, 1);
  assert.equal(parsed?.uniqueUnwindInfoCount, 1);
  assert.deepEqual(parsed?.beginRvas, [0x2004]);
  assert.match(parsed?.issues.join(" | ") ?? "", /Indirect.*origin.*unknown/i);
  assert.deepEqual(warnings, []);
});

for (const pointer of [0, 0x20]) {
  void test(`ARM64 exception copies preserve their existing RVA-based decoder at pointer ${pointer}`, async () => {
    const bytes = subject().data.slice();
    const view = new DataView(bytes.buffer);
    [0x2004, 5, 0x2008, 5].forEach((value, index) => view.setUint32(0x20 + index * 4, value, true));
    const warnings: string[] = [];
    const warn = (warning: string) => warnings.push(warning);
    const file = new MockFile(bytes);
    const parsed = await parseExceptionDebugInfo(file, mapRva, 0x4000, pointer, 16,
      0xaa64, warn, { ...exception, size: 16 });

    assert.equal(parsed?.functionCount, 2);
    assert.equal(parsed?.invalidEntryCount, 0);
    assert.deepEqual(parsed?.beginRvas, [0x2004, 0x2008]);
    assert.deepEqual(parsed?.issues, []);
    assert.deepEqual(warnings, []);
    assert.equal(await parseExceptionDebugInfo(file, mapRva, 0, file.size, 16, 0xaa64, warn, exception), null);
    assert.match(warnings[0]!, /starts past end/);
  });
}

void test("ARM64 copies retain low function RVAs in the image instead of treating them as copy coordinates", async () => {
  const bytes = subject().data.slice();
  const view = new DataView(bytes.buffer);
  [0x800, 5, 0x804, 5].forEach((value, index) => view.setUint32(0x20 + index * 4, value, true));
  const parsed = await parseExceptionDebugInfo(new MockFile(bytes),
    rva => rva >= 0x800 && rva < 0x808 ? 0x80 + rva - 0x800 : mapRva(rva),
    0, 0x20, 16, 0xaa64, assert.fail, { ...exception, size: 16 });

  assert.equal(parsed?.invalidEntryCount, 0);
  assert.deepEqual(parsed?.beginRvas, [0x800, 0x804]);
});

void test("ARM64 .xdata at the table-end RVA remains image data", async () => {
  const bytes = subject().data.slice();
  const view = new DataView(bytes.buffer);
  [0x2004, 0x1010, 0x2008, 5].forEach((value, index) => view.setUint32(0x20 + index * 4, value, true));
  view.setUint32(0x90, 1 | (1 << 21) | (1 << 27), true); // Length=4, E=1, one code word.
  bytes[0x94] = 0xe4; // Minimal complete END sequence; the remaining word bytes are padding.
  const parsed = await parseExceptionDebugInfo(new MockFile(bytes),
    rva => rva >= 0x1010 && rva < 0x1018 ? 0x90 + rva - 0x1010 : mapRva(rva),
    0, 0x20, 16, 0xaa64, assert.fail, { ...exception, size: 16 });

  assert.equal(parsed?.invalidEntryCount, 0);
  assert.deepEqual(parsed?.rangeLengths, [4, 4]);
  assert.deepEqual(parsed?.issues, []);
});

void test("raw-only AMD64 copies do not substitute invented table RVAs for low image references", async () => {
  const bytes = subject().data.slice();
  const view = new DataView(bytes.buffer);
  [4, 8, 16, 8, 12, 16].forEach((value, index) => view.setUint32(0x20 + index * 4, value, true));
  const parsed = await parseExceptionDebugInfo(new MockFile(bytes), rva =>
    rva >= 4 && rva < 12 ? 0x80 + rva - 4 : rva >= 16 && rva < 20 ? 0x90 + rva - 16 : null,
    0, 0x20, 24, 0x8664, assert.fail);

  assert.deepEqual(parsed?.beginRvas, [4, 8]);
  assert.equal(parsed?.uniqueUnwindInfoCount, 1);
  assert.deepEqual(parsed?.issues, []);
});

void test("raw-only AMD64 copies diagnose trailing bytes after complete rows", async () => {
  const bytes = subject().data.slice();
  new DataView(bytes.buffer).setUint32(0x28, 0x3000, true);
  const parsed = await parseExceptionDebugInfo(new MockFile(bytes), mapRva, 0, 0x20, 13, 0x8664, assert.fail);

  assert.equal(parsed?.functionCount, 1);
  assert.match(parsed?.issues.join(" | ") ?? "", /not a multiple/);
});

void test("mapped .pdata copy keeps its physical location separate from its original table RVA", async () => {
  const file = subject();
  const warnings: string[] = [];
  const parsed = await parseExceptionDebugInfo(file, mapRva, 0x4000, 0, 24,
    0x8664, warning => warnings.push(warning), exception);

  assert.equal(parsed?.functionCount, 2);
  assert.equal(parsed?.invalidEntryCount, 0);
  assert.deepEqual(parsed?.issues, []);
  assert.deepEqual(warnings, []);
});

void test("Debug Directory passes the actual Exception Table origin into the payload decoder", async () => {
  const bytes = new Uint8Array(0xc0);
  bytes.set(subject().data);
  const view = new DataView(bytes.buffer);
  view.setUint32(0xac, 5, true);
  view.setUint32(0xb0, 24, true);
  view.setUint32(0xb8, 0x20, true);
  const file = new MockFile(bytes);
  const parsed = await parseDebugDirectory(file, [{ name: "DEBUG", rva: 0x5000, size: 28 }, exception],
    rva => rva >= 0x5000 && rva < 0x501c ? 0xa0 + rva - 0x5000 : mapRva(rva), 0x8664);

  assert.equal(parsed.entries[0]?.exception?.functionCount, 2);
  assert.equal(parsed.entries[0]?.exception?.invalidEntryCount, 0);
  assert.deepEqual(parsed.entries[0]?.exception?.issues, []);
  assert.equal(parsed.entries[0]?.rawPayload, undefined);
  assert.equal(parsed.warning, null);
});

void test("RVA-only exception copies preserve fragmented physical mappings", async () => {
  const bytes = subject().data.slice();
  bytes.set(bytes.subarray(0x2c, 0x38), 0x60);
  bytes.fill(0, 0x2c, 0x38);
  const file = new MockFile(bytes);
  const warnings: string[] = [];
  const parsed = await parseExceptionDebugInfo(file,
    rva => rva >= 0x400c && rva < 0x4018 ? 0x60 + rva - 0x400c : mapRva(rva),
    0x4000, 0, 24, 0x8664, warning => warnings.push(warning), exception);

  assert.equal(parsed?.functionCount, 2);
  assert.equal(parsed?.invalidEntryCount, 0);
  assert.deepEqual(parsed?.issues, []);
  assert.deepEqual(warnings, []);
});

void test("exception-copy mapping leaves function addresses below the table origin in the image", async () => {
  const bytes = subject().data.slice();
  const view = new DataView(bytes.buffer);
  view.setUint32(0x20, 0x800, true);
  view.setUint32(0x24, 0x804, true);
  const file = new MockFile(bytes);
  const parsed = await parseExceptionDebugInfo(file,
    rva => rva >= 0x800 && rva < 0x804 ? 0x80 + rva - 0x800 : mapRva(rva),
    0, 0x20, 24, 0x8664, assert.fail, exception);

  assert.equal(parsed?.invalidEntryCount, 0);
  assert.equal(parsed?.beginRvas[0], 0x800);
});

void test("exception copy without main-table context still decodes direct references at its recorded RVA", async () => {
  const bytes = subject().data.slice();
  new DataView(bytes.buffer).setUint32(0x28, 0x3000, true);
  const file = new MockFile(bytes);
  const parsed = await parseExceptionDebugInfo(file, mapRva, 0x4000, 0x20, 24, 0x8664, assert.fail);

  assert.equal(parsed?.functionCount, 2);
  assert.equal(parsed?.invalidEntryCount, 0);
});

void test("exception copies report missing origins, unmapped sources and out-of-file pointers", async () => {
  const file = subject();
  const warnings: string[] = [];
  const warn = (warning: string) => warnings.push(warning);

  assert.equal(await parseExceptionDebugInfo(file, mapRva, 0, 0x20, 24, 0x14c, warn), null);
  assert.equal(await parseExceptionDebugInfo(file, mapRva, 0x9000, 0, 24, 0x8664, warn), null);
  assert.equal(await parseExceptionDebugInfo(file, mapRva, 0, file.size, 24, 0x8664, warn, exception), null);
  assert.match(warnings.join(" | "), /no known table RVA/);
  assert.match(warnings[1]!, /^EXCEPTION debug entry does not map/);
  assert.match(warnings[2]!, /^EXCEPTION debug entry starts past end of file/);
});

void test("empty or negative exception payloads do not produce misleading location warnings", async () => {
  const file = subject();
  const warnings: string[] = [];
  const warn = (warning: string) => warnings.push(warning);

  assert.equal(await parseExceptionDebugInfo(file, mapRva, 0, 0, 0, 0x8664, warn), null);
  assert.equal(await parseExceptionDebugInfo(file, mapRva, 0, 0, -1, 0x8664, warn), null);
  assert.deepEqual(warnings, []);
});

void test("exception copies keep truncated-data diagnostics and accept an empty payload", async () => {
  const file = subject();
  const warnings: string[] = [];
  const warn = (warning: string) => warnings.push(warning);
  const parsed = await parseExceptionDebugInfo(file, mapRva, 0, 0x98, 24, 0x8664, warn, exception);

  assert.equal(parsed?.functionCount, 0);
  assert.match(parsed?.issues.join(" | ") ?? "", /truncated|complete RUNTIME_FUNCTION/);
  assert.match(warnings.join(" | "), /shorter than its declared SizeOfData/);
  assert.equal(await parseExceptionDebugInfo(file, mapRva, 0, 0, 0, 0x8664, warn), null);
});

void test("exception copy reads its first byte from the copy and leaves table-end unwind metadata in the image", async () => {
  const bytes = subject().data.slice();
  const view = new DataView(bytes.buffer);
  view.setUint32(0x20, 0x2001, true);
  view.setUint32(0x34, 0x1018, true);
  const file = new MockFile(bytes);
  const parsed = await parseExceptionDebugInfo(file,
    rva => rva >= 0x1018 && rva < 0x101c ? 0x90 + rva - 0x1018 : mapRva(rva),
    0, 0x20, 24, 0x8664, assert.fail, exception);

  assert.equal(parsed?.beginRvas[0], 0x2001);
  assert.equal(parsed?.invalidEntryCount, 0);
  assert.equal(parsed?.uniqueUnwindInfoCount, 1);
  assert.deepEqual(parsed?.issues, []);
});

void test("unsupported exception-copy machines with a known origin retain an explicit diagnostic", async () => {
  const parsed = await parseExceptionDebugInfo(subject(), mapRva, 0, 0x20, 24,
    0xdead, assert.fail, exception);

  assert.equal(parsed?.functionCount, 0);
  assert.deepEqual(parsed?.issues, ["Exception directory decoding is not implemented for machine 0xdead."]);
});

for (const [size, count, issues] of [
  [11, 0, ["Exception directory size is smaller than one RUNTIME_FUNCTION entry (12 bytes)."]],
  [12, 1, []]
] as const) {
  void test(`AMD64 debug copy with declared size ${size} preserves the one-row boundary`, async () => {
    const bytes = subject().data.slice();
    new DataView(bytes.buffer).setUint32(0x28, 0x3000, true);
    const parsed = await parseExceptionDebugInfo(new MockFile(bytes), mapRva, 0, 0x20, size, 0x8664, assert.fail);

    assert.equal(parsed?.functionCount, count);
    assert.deepEqual(parsed?.issues, issues);
  });
}
