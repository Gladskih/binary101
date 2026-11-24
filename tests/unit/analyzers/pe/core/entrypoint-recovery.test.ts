import assert from "node:assert/strict";
import { test } from "node:test";
import { isPeWindowsCore, parsePeHeaders } from "../../../../../analyzers/pe/core/index.js";
import { createPeWithShortOptionalHeader } from "../../../../fixtures/pe-short-optional-header.js";
import { MockFile } from "../../../../helpers/mock-file.js";

void test("recovers a file-backed low-alignment entry point outside the optional header", async () => {
  const core = await parsePeHeaders(new MockFile(createPeWithShortOptionalHeader(), "short.bin"));

  assert.ok(core && isPeWindowsCore(core));
  assert.equal(core.opt.AddressOfEntryPoint, 0);
  assert.equal(core.rvaToOff(0x100), null);
  assert.equal(core.recoveredEntrypoint?.rva, 0x100);
});

void test("does not recover an entry point from incomplete or unbacked image data", async () => {
  const bytes = createPeWithShortOptionalHeader();
  const view = new DataView(bytes.buffer);
  const truncated = await parsePeHeaders(new MockFile(bytes.subarray(0, 0x94), "short.bin"));
  view.setUint32(0x68, bytes.length, true);
  view.setUint32(0x90, bytes.length * 2, true);
  const unbacked = await parsePeHeaders(new MockFile(bytes, "short.bin"));

  assert.ok(truncated && isPeWindowsCore(truncated));
  assert.ok(unbacked && isPeWindowsCore(unbacked));
  assert.equal(truncated.recoveredEntrypoint, undefined);
  assert.equal(unbacked.recoveredEntrypoint, undefined);
});

// File offsets in the short PE fixture. The alignment cases set both fields because matching
// each other is insufficient: the value must be a nonzero power of two below one page.
const invalidHeaders: Array<[string, (view: DataView) => void]> = [
  ["non-executable COFF characteristics", view => view.setUint16(0x56, 0, true)],
  ["AMD64 machine with PE32 magic", view => view.setUint16(0x44, 0x8664, true)],
  ["x86 machine with PE32+ magic", view => view.setUint16(0x58, 0x20b, true)],
  ["zero entry point", view => view.setUint32(0x68, 0, true)],
  ["different FileAlignment", view => view.setUint32(0x7c, 8, true)],
  ["zero alignments", view => view.setBigUint64(0x78, 0n, true)],
  ["non-power-of-two alignments", view => view.setBigUint64(0x78, 0x300000003n, true)],
  ["page-aligned image", view => view.setBigUint64(0x78, 0x100000001000n, true)],
  ["SizeOfHeaders ending before the declared header", view => view.setUint32(0x94, 0x5f, true)],
  ["SizeOfHeaders extending beyond the file", view => view.setUint32(0x94, view.byteLength + 1, true)]
];

for (const [reason, edit] of invalidHeaders) {
  void test(`does not recover an entry point with ${reason}`, async () => {
    const bytes = createPeWithShortOptionalHeader();
    edit(new DataView(bytes.buffer));

    const core = await parsePeHeaders(new MockFile(bytes, "short.bin"));

    assert.ok(core && isPeWindowsCore(core));
    assert.equal(core.recoveredEntrypoint, undefined);
  });
}

void test("limits the recovered flat range to the image and accepts exact header bounds", async () => {
  const bytes = createPeWithShortOptionalHeader();
  const view = new DataView(bytes.buffer);
  // The extent of the declared headers is 0x58 + 8 and the image ends before the file.
  view.setUint32(0x94, 0x60, true);
  view.setUint32(0x90, 0x140, true);

  const core = await parsePeHeaders(new MockFile(bytes, "short.bin"));

  assert.ok(core && isPeWindowsCore(core));
  assert.equal(core.recoveredEntrypoint?.flatRvaLimit, 0x140);
});

void test("reads the 64-bit image base for a short PE32+ header", async () => {
  const bytes = createPeWithShortOptionalHeader();
  const view = new DataView(bytes.buffer);
  // AMD64 and PE32+ with ImageBase at optional header +24.
  view.setUint16(0x44, 0x8664, true);
  view.setUint16(0x58, 0x20b, true);
  view.setBigUint64(0x70, 0x140000000n, true);

  const core = await parsePeHeaders(new MockFile(bytes, "short.bin"));

  assert.ok(core && isPeWindowsCore(core));
  assert.equal(core.recoveredEntrypoint?.rva, 0x100);
  assert.equal(core.recoveredEntrypoint?.imageBase, 0x140000000n);
});

void test("does not recover an entry point with a complete declared field", async () => {
  const bytes = createPeWithShortOptionalHeader();
  // SizeOfOptionalHeader covers the entire entry point DWORD at +16.
  new DataView(bytes.buffer).setUint16(0x54, 20, true);

  const core = await parsePeHeaders(new MockFile(bytes, "short.bin"));

  assert.ok(core && isPeWindowsCore(core));
  assert.equal(core.opt.AddressOfEntryPoint, 0x100);
  assert.equal(core.recoveredEntrypoint, undefined);
});

void test("recovers a section-backed entry point only when the section permits execution", async () => {
  const bytes = createPeWithShortOptionalHeader();
  const view = new DataView(bytes.buffer);
  // A 16-byte optional header puts its entry point field over the section name.
  // The section's virtual address also supplies the raw ImageBase field.
  view.setUint16(0x46, 1, true);
  view.setUint16(0x54, 16, true);
  view.setUint32(0x68, 0x10000, true);
  view.setUint32(0x70, 16, true);
  view.setUint32(0x74, 0x10000, true);
  view.setUint32(0x78, 16, true);
  view.setUint32(0x7c, 0x120, true);
  view.setUint32(0x90, 0x11000, true);
  // IMAGE_SCN_MEM_EXECUTE in the section's Characteristics field.
  view.setUint32(0x8c, 0x20000000, true);
  const executable = await parsePeHeaders(new MockFile(bytes, "short.bin"));
  view.setUint32(0x8c, 0, true);
  const nonExecutable = await parsePeHeaders(new MockFile(bytes, "short.bin"));

  assert.ok(executable && isPeWindowsCore(executable));
  assert.ok(nonExecutable && isPeWindowsCore(nonExecutable));
  assert.deepEqual(executable.recoveredEntrypoint, { rva: 0x10000, imageBase: 0x10000n });
  assert.equal(executable.rvaToOff(0x10000), 0x120);
  assert.equal(nonExecutable.recoveredEntrypoint, undefined);
});
