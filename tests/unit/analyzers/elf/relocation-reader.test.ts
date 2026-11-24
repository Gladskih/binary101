import assert from "node:assert/strict";
import { test } from "node:test";
import { createFileRangeReader } from "../../../../analyzers/file-range-reader.js";
import { elfFileRange, elfVirtualExtent, elfVirtualRange, readElfRelocationString } from
  "../../../../analyzers/elf/relocation-reader.js";
import { elfLoadMappingCovers } from "../../../../analyzers/elf/range-coverage.js";
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

for (const [name, delta, offsetDelta, extent, covered] of [
  ["adjacent", 0n, 0n, 514, true], ["same translation overlap", -1n, -1n, 514, true],
  ["virtual gap", 1n, 1n, 2, false], ["different translation", 0n, 1n, 2, false],
  ["conflicting overlap", -1n, 0n, 1, false]
] as const) {
  void test(`uses the same file-backed coverage for validation and reading with ${name}`, () => {
    const { elf } = dynamicRelocationFixture();
    const first = { ...elf.programHeaders[0]!, filesz: 512n, memsz: 512n };
    const second = { ...first, index: 1, offset: 512n + offsetDelta, vaddr: first.vaddr + 512n + delta,
      filesz: 512n - delta, memsz: 512n - delta };
    const headers = [second, first];
    const start = first.vaddr + 510n;

    assert.equal(elfLoadMappingCovers(headers, 510n, start, 4n), covered);
    assert.deepEqual(elfVirtualRange(headers, start, 4n, elf.fileSize), covered ? { offset: 510, size: 4 } : null);
    assert.deepEqual(elfVirtualExtent(headers, start, elf.fileSize), { offset: 510, size: extent });
  });
}

void test("rejects directly ambiguous virtual bytes and caps variable-length reads at EOF", () => {
  const { elf } = dynamicRelocationFixture();
  const load = elf.programHeaders[0]!;

  assert.equal(elfVirtualRange([load, { ...load, offset: 1n }], load.vaddr, 1n, elf.fileSize), null);
  assert.equal(elfVirtualExtent([load, { ...load, offset: 1n }], load.vaddr, elf.fileSize), null);
  assert.deepEqual(elfVirtualExtent([load], load.vaddr + 409n, 411), { offset: 409, size: 2 });
  assert.equal(elfVirtualRange([load], load.vaddr + 409n, 3n, 411), null);
  assert.equal(elfVirtualExtent([load], load.vaddr + 411n, 411), null);
  assert.deepEqual(elfVirtualRange([load], load.vaddr + load.filesz, 0n, elf.fileSize),
    { offset: elf.fileSize, size: 0 });
  assert.equal(elfVirtualRange([load], load.vaddr + load.filesz + 1n, 0n, elf.fileSize), null);
  assert.equal(elfLoadMappingCovers([load], load.filesz, load.vaddr + load.filesz, 0n), true);
  assert.equal(elfLoadMappingCovers([load], 0n, load.vaddr + load.filesz, 0n), false);
});

void test("empty ranges require a valid PT_LOAD anchor at the requested address", () => {
  const { elf } = dynamicRelocationFixture();
  const load = { ...elf.programHeaders[0]!, offset: 16n, filesz: 32n, memsz: 32n };

  assert.deepEqual(elfVirtualRange([load], load.vaddr, 0n, elf.fileSize), { offset: 16, size: 0 });
  assert.equal(elfVirtualRange([load], load.vaddr - 1n, 0n, elf.fileSize), null);
  assert.equal(elfVirtualRange([load], load.vaddr + load.filesz + 1n, 0n, elf.fileSize), null);
  assert.equal(elfVirtualRange([{ ...load, type: 4 }], load.vaddr, 0n, elf.fileSize), null);
});

void test("a different translation ending at the start does not conflict with file-backed bytes", () => {
  const { elf } = dynamicRelocationFixture();
  const head = { ...elf.programHeaders[0]!, offset: 0n, vaddr: 0n, filesz: 32n, memsz: 32n };
  const next = { ...head, offset: 64n, vaddr: 32n };

  assert.deepEqual(elfVirtualRange([head, next], 0n, 1n, elf.fileSize), { offset: 0, size: 1 });
  assert.deepEqual(elfVirtualRange([head, next], 32n, 1n, elf.fileSize), { offset: 64, size: 1 });
  assert.equal(elfVirtualRange([{ ...head, vaddr: -1n }], -1n, 1n, elf.fileSize), null);
});

void test("clips at the earliest conflicting translation regardless of program header order", () => {
  const { elf } = dynamicRelocationFixture();
  const load = elf.programHeaders[0]!;
  const early = { ...load, offset: 500n, vaddr: load.vaddr + 100n, filesz: 4n, memsz: 4n };
  const late = { ...early, vaddr: load.vaddr + 200n };

  assert.deepEqual(elfVirtualExtent([early, late, load], load.vaddr, elf.fileSize), { offset: 0, size: 100 });
  assert.deepEqual(elfVirtualRange([late, early, load], load.vaddr, 100n, elf.fileSize), { offset: 0, size: 100 });
  assert.equal(elfLoadMappingCovers([load], 1n, load.vaddr, 20n), false);
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
