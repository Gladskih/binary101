import assert from "node:assert/strict";
import { test } from "node:test";
import { createFileRangeReader } from "../../../../analyzers/file-range-reader.js";
import { elfFileRange, elfVirtualRange, readElfRelocationString } from
  "../../../../analyzers/elf/relocation-reader.js";
import { dynamicRelocationFixture } from "../../../fixtures/elf-dynamic-relocations.js";

void test("file and virtual ranges validate their entire extent including memory tails", () => {
  const fixture = dynamicRelocationFixture();

  assert.deepEqual(elfFileRange(1020n, 4n, 1024), { offset: 1020, size: 4 });
  assert.equal(elfFileRange(1020n, 5n, 1024), null);
  assert.equal(elfFileRange(-1n, 1n, 1024), null);
  assert.equal(elfFileRange(0n, -1n, 1024), null);
  assert.equal(elfFileRange(1n << 60n, 0n, 1024), null);
  assert.deepEqual(elfVirtualRange(fixture.elf.programHeaders, 0x13fcn, 4n, 1024),
    { offset: 1020, size: 4 });
  assert.equal(elfVirtualRange(fixture.elf.programHeaders, 0x13fcn, 5n, 1024), null);
  assert.equal(elfVirtualRange(fixture.elf.programHeaders, 0x1400n, 1n, 1024), null);
  assert.equal(elfVirtualRange(fixture.elf.programHeaders, -1n, 1n, 1024), null);
  assert.equal(elfVirtualRange(fixture.elf.programHeaders, 0x1000n, -1n, 1024), null);
  fixture.elf.programHeaders[0]!.memsz = 1n;
  assert.equal(elfVirtualRange(fixture.elf.programHeaders, 0x1000n, 1n, 1024), null);
});

void test("symbol names are bounded, terminated and decoded", async () => {
  const fixture = dynamicRelocationFixture();
  const reader = createFileRangeReader(fixture.file(), 0, fixture.bytes.length);
  const issues: string[] = [];

  assert.equal(await readElfRelocationString(reader, 385n, 7n, issues), "target");
  assert.equal(await readElfRelocationString(reader, 384n, 1n, issues), "");
  assert.deepEqual(issues, []);
  assert.equal(await readElfRelocationString(reader, 385n, 3n, issues), "tar");
  assert.equal(await readElfRelocationString(reader, 1024n, 1n, issues), "");
  assert.match(issues.join(" "), /unterminated/);
  assert.match(issues.join(" "), /outside/);
});

void test("symbol decoding preserves UTF-8 split across short reads", async () => {
  const bytes = new TextEncoder().encode("a€z\0ignored");
  const reader = createFileRangeReader(new File([bytes], "string-table"), 0, bytes.length);
  const issues: string[] = [];

  const name = await readElfRelocationString({ ...reader,
    // Two-byte reads split the three-byte UTF-8 encoding of the euro sign.
    read: (offset, size) => reader.read(offset, Math.min(size, 2))
  }, 0n, BigInt(bytes.length), issues);

  assert.equal(name, "a€z");
  assert.deepEqual(issues, []);
});

void test("symbol decoding stops when the reader makes no progress", async () => {
  const bytes = new TextEncoder().encode("name");
  const reader = createFileRangeReader(new File([bytes], "string-table"), 0, bytes.length);
  const issues: string[] = [];

  assert.equal(await readElfRelocationString({ ...reader,
    read: async () => new DataView(new ArrayBuffer(0))
  }, 0n, BigInt(bytes.length), issues), "");
  assert.match(issues.join(" "), /unterminated/);
});

void test("chunked symbol reads stop at the string-table boundary before neighboring bytes", async () => {
  const bytes = new TextEncoder().encode("name\0neighbor");
  const reader = createFileRangeReader(new File([bytes], "string-table"), 0, bytes.length);
  const issues: string[] = [];

  const name = await readElfRelocationString({ ...reader,
    // Force partial reads, leaving the NUL outside the declared four-byte table.
    read: (offset, size) => reader.read(offset, Math.min(size, 3))
  }, 0n, BigInt("name".length), issues);

  assert.equal(name, "name");
  assert.deepEqual(issues, ["Relocation symbol name is unterminated."]);
});
