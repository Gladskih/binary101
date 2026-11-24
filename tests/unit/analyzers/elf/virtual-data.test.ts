import assert from "node:assert/strict";
import { test } from "node:test";
import { createFileRangeReader } from "../../../../analyzers/file-range-reader.js";
import { elfVirtualDataRange, openElfDataRange } from "../../../../analyzers/elf/virtual-data.js";
import { dynamicRelocationFixture } from "../../../fixtures/elf-dynamic-relocations.js";
import { expectDefined } from "../../../helpers/expect-defined.js";
import { elfLoadFileFragments } from "../../../../analyzers/elf/range-coverage.js";

const fragmented = () => {
  const template = dynamicRelocationFixture().elf.programHeaders[0]!;
  const address = template.vaddr;
  const first = { ...template, offset: 20n, filesz: 2n, memsz: 2n };
  const second = { ...first, offset: 22n, vaddr: address + 2n };
  const third = { ...first, offset: 4n, vaddr: address + 4n, filesz: 4n, memsz: 4n };
  const bytes = new Uint8Array(32);
  bytes.set([1, 2, 3, 4], 20);
  bytes.set([5, 6, 7, 8], 4);
  const file = new File([bytes], "virtual-range");
  const reader = createFileRangeReader(file, 0, file.size);
  return { first, second, third, address, reader, headers: [third, second, first] };
};

void test("coalesces adjacent physical bytes and reads fragments in virtual order", async () => {
  const { headers, address, reader } = fragmented();
  const range = expectDefined(elfVirtualDataRange(headers, address, 8n, reader.size));

  assert.deepEqual(range, { offset: 20, size: 8, fragments: [{ offset: 20, size: 4 }, { offset: 4, size: 4 }] });
  const source = openElfDataRange(reader, range);
  assert.equal(source.offset, 0);
  assert.deepEqual(await source.reader.readBytes(2, 4), Uint8Array.of(3, 4, 5, 6));
  assert.deepEqual(await source.reader.readBytes(4, 2), Uint8Array.of(5, 6));
  assert.deepEqual(await source.reader.readBytes(7, 5), Uint8Array.of(8));
  assert.equal((await source.reader.read(2, 4)).getUint32(0, false), 0x03040506);
});

void test("retains the ordinary file reader when the range has one physical slice", () => {
  const { headers, address, reader } = fragmented();
  const range = expectDefined(elfVirtualDataRange(headers, address, 4n, reader.size));

  assert.deepEqual(openElfDataRange(reader, range), { offset: 20, size: 4, reader });
});

void test("accepts matching overlapping aliases and clips the final fragment to the requested size", () => {
  const { first, third, address, reader } = fragmented();
  const headers = [{ ...first, filesz: 4n, memsz: 4n }, third,
    { ...first, offset: 21n, vaddr: address + 1n, filesz: 1n, memsz: 1n }];

  assert.deepEqual(elfVirtualDataRange(headers, address, 5n, reader.size),
    { offset: 20, size: 5, fragments: [{ offset: 20, size: 4 }, { offset: 4, size: 1 }] });
});

void test("ignores empty segments and segments outside the requested byte range", () => {
  const { first, headers, address, reader } = fragmented();
  headers.push({ ...first, offset: 10n, vaddr: address + 3n, filesz: 0n },
    { ...first, offset: 16n, vaddr: address + 9n },
    { ...first, offset: 16n, filesz: 1n });

  assert.deepEqual(elfVirtualDataRange(headers, address + 1n, 7n, reader.size),
    { offset: 21, size: 7, fragments: [{ offset: 21, size: 3 }, { offset: 4, size: 4 }] });
});

void test("handles virtual address zero and rejects empty, negative and oversized fragmented queries", () => {
  const { first, headers, address, reader } = fragmented();
  for (const header of headers) header.vaddr -= address;
  const negative = { ...first, vaddr: -1n };

  assert.equal(elfLoadFileFragments([negative], -1n, 1n), null);
  assert.equal(elfLoadFileFragments(headers, 0n, 0n), null);
  assert.equal(elfLoadFileFragments(headers, 0n, -1n), null);
  assert.equal(elfVirtualDataRange(headers, 0n, 8n, reader.size)?.size, 8);
  // The same physical span is mapped twice. The virtual span can be larger than fileSize.
  const half = 1n << 52n;
  const large = { ...first, offset: 0n, filesz: half, memsz: half };
  const repeated = [large, { ...large, vaddr: half }];
  assert.equal(elfVirtualDataRange(repeated, 0n, half * 2n, Number(half)), null);
  assert.equal(elfVirtualDataRange(repeated, 0n, half * 2n - 1n, Number(half))?.size, Number.MAX_SAFE_INTEGER);
});

for (const [label, change] of [
  ["gap", { vaddr: 0x1005n }], ["conflicting overlap", { vaddr: 0x1003n, filesz: 5n, memsz: 5n }],
  ["non-load", { type: 4 }], ["zero-fill", { filesz: 0n }], ["invalid load size", { memsz: 3n }],
  ["outside the file", { offset: 30n }]
] as const) {
  void test(`rejects a fragmented range with a ${label}`, () => {
    const { headers, third, address, reader } = fragmented();
    Object.assign(third, change);

    assert.equal(elfVirtualDataRange(headers, address, 8n, reader.size), null);
  });
}

void test("rejects out-of-bounds reads and stops at short underlying reads", async () => {
  const { headers, address, reader } = fragmented();
  const range = expectDefined(elfVirtualDataRange(headers, address, 8n, reader.size));
  const short = { ...reader, readBytes: (offset: number, size: number) => reader.readBytes(offset, Math.min(size, 1)) };
  const source = openElfDataRange(short, range);

  assert.deepEqual(await source.reader.readBytes(2, 4), Uint8Array.of(3));
  const guarded = openElfDataRange({ ...reader, readBytes: (offset, size) => {
    assert.ok(size > 0);
    return reader.readBytes(offset, offset === 4 ? Math.min(size, 1) : size);
  } }, range);
  assert.deepEqual(await guarded.reader.readBytes(2, 6), Uint8Array.of(3, 4, 5));
  assert.deepEqual(await guarded.reader.readBytes(4, 1), Uint8Array.of(5));
  for (const [offset, length] of [[-1, 4], [8, 1], [1, 0], [0.5, 1], [1, Number.NaN]]) {
    assert.equal((await guarded.reader.read(offset!, length!)).byteLength, 0);
  }
});

void test("indexes a later fragment without requesting bytes from earlier fragments", async () => {
  const { reader } = fragmented();
  const source = openElfDataRange({ ...reader, readBytes: (offset, size) => {
    assert.ok(size > 0);
    return reader.readBytes(offset, size);
  } }, { offset: 20, size: 8, fragments: [{ offset: 20, size: 4 }, { offset: 4, size: 2 }, { offset: 22, size: 2 }] });

  assert.deepEqual(await source.reader.readBytes(6, 2), Uint8Array.of(3, 4));
  assert.deepEqual(await source.reader.readBytes(2, 6), Uint8Array.of(3, 4, 5, 6, 3, 4));
});

void test("uses the underlying view directly when a read stays inside one fragment", async () => {
  const { headers, address, reader } = fragmented();
  const range = expectDefined(elfVirtualDataRange(headers, address, 8n, reader.size));
  const bytes = await reader.readBytes(20, 2);
  const source = openElfDataRange({ ...reader, readBytes: async () => bytes }, range);

  assert.equal(await source.reader.readBytes(0, bytes.length), bytes);
});
