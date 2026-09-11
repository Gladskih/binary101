import assert from "node:assert/strict";
import { test } from "node:test";
import { readMappedNullTerminatedAsciiString } from
  "../../../../../analyzers/pe/strings/mapped-ascii-string.js";
import { MockFile } from "../../../../helpers/mock-file.js";

void test("mapped ASCII strings follow adjacent RVAs across discontiguous file ranges", async () => {
  const file = new MockFile(new TextEncoder().encode("rted\0----Expo"));
  const mapping = (rva: number): number => rva < 4 ? 9 + rva : rva - 4;

  assert.deepEqual(await readMappedNullTerminatedAsciiString(
    file, file.size, mapping, 0, 9
  ), { text: "Exported", terminated: true, mappingStopped: false });
});

void test("mapped ASCII strings stop at unmapped data and the requested limit", async () => {
  const file = new MockFile(new TextEncoder().encode("ABC\0"));

  assert.deepEqual(await readMappedNullTerminatedAsciiString(
    file, file.size, rva => rva < 2 ? rva : null, 0, file.size
  ), { text: "AB", terminated: false, mappingStopped: true });
  assert.deepEqual(await readMappedNullTerminatedAsciiString(
    file, file.size, rva => rva, 0, 2, 1
  ), { text: "AB", terminated: false, mappingStopped: false });
});

void test("mapped ASCII strings never wrap an RVA at the 32-bit limit", async () => {
  const file = new MockFile(new TextEncoder().encode("AB\0"));

  // Microsoft PE/COFF: RVA fields are 32-bit; 0x100000000 is not RVA zero.
  assert.deepEqual(await readMappedNullTerminatedAsciiString(
    file, file.size, rva => rva === 0 ? 2 : rva - 0xfffffffe, 0xfffffffe, 3
  ), { text: "AB", terminated: false, mappingStopped: true });
});

void test("mapped ASCII strings preserve a prefix when file reads are short", async () => {
  const file = new MockFile(new TextEncoder().encode("AB"));

  assert.deepEqual(await readMappedNullTerminatedAsciiString(
    { ...file, size: 4, read: (offset, size) => file.read(offset, size),
      readBytes: (offset, size) => file.readBytes(offset, size) },
    4, rva => rva, 0, 4
  ), { text: "AB", terminated: false, mappingStopped: false });
});

void test("mapped ASCII strings reject unreadable starts", async () => {
  const file = new MockFile(new TextEncoder().encode("AB"));

  assert.equal(await readMappedNullTerminatedAsciiString(file, file.size, () => null, 0, 2), null);
  assert.equal(await readMappedNullTerminatedAsciiString(file, file.size, () => -1, 0, 2), null);
  assert.equal(await readMappedNullTerminatedAsciiString(file, file.size, () => 2, 0, 2), null);
  assert.equal(await readMappedNullTerminatedAsciiString(file, file.size, rva => rva, 0, 0), null);
});

for (const invalid of [Number.NaN, Number.POSITIVE_INFINITY, -1, 0.5]) {
  void test(`mapped ASCII strings reject invalid ranges: ${invalid}`, async () => {
    const file = new MockFile(new TextEncoder().encode("AB\0"));

    assert.equal(await readMappedNullTerminatedAsciiString(
      file, file.size, rva => rva, invalid, 3
    ), null);
    assert.equal(await readMappedNullTerminatedAsciiString(
      file, file.size, rva => rva, 0, invalid
    ), null);
    assert.equal(await readMappedNullTerminatedAsciiString(
      file, file.size, rva => rva, 0, 3, invalid
    ), null);
    assert.equal(await readMappedNullTerminatedAsciiString(
      file, file.size, () => invalid, 0, 3
    ), null);
  });
}

void test("mapped ASCII strings handle empty strings, chunk boundaries and EOF", async () => {
  const file = new MockFile(new TextEncoder().encode("AB\0"));

  assert.deepEqual(await readMappedNullTerminatedAsciiString(
    file, file.size, rva => rva, 2, 1
  ), { text: "", terminated: true, mappingStopped: false });
  assert.deepEqual(await readMappedNullTerminatedAsciiString(
    file, file.size, rva => rva, 0, 3, 1
  ), { text: "AB", terminated: true, mappingStopped: false });
  assert.deepEqual(await readMappedNullTerminatedAsciiString(
    file, 2, rva => rva, 0, 3
  ), { text: "AB", terminated: false, mappingStopped: true });
  assert.equal(await readMappedNullTerminatedAsciiString(
    file, file.size, rva => rva, 0, 3, 0
  ), null);
  assert.equal(await readMappedNullTerminatedAsciiString(
    file, file.size, () => 0, 0x100000000, 3
  ), null);
  assert.equal(await readMappedNullTerminatedAsciiString(
    file, file.size, () => 0, -1, 3
  ), null);
});

void test("mapped ASCII strings batch reads without crossing byte or file limits", async () => {
  const file = new MockFile(new TextEncoder().encode("----ABCDE\0"));
  const reads: number[][] = [];
  const reader = {
    size: file.size,
    read: (offset: number, size: number) => {
      reads.push([offset, size]);
      return file.read(offset, size);
    },
    readBytes: (offset: number, size: number) => file.readBytes(offset, size)
  };

  assert.deepEqual(await readMappedNullTerminatedAsciiString(
    reader, file.size, rva => rva, 4, 4, 3
  ), { text: "ABCD", terminated: false, mappingStopped: false });
  assert.deepEqual(reads, [[4, 3], [7, 1]]);
  reads.length = 0;
  assert.deepEqual(await readMappedNullTerminatedAsciiString(
    reader, 8, rva => rva, 4, 6, 3
  ), { text: "ABCD", terminated: false, mappingStopped: true });
  assert.deepEqual(reads, [[4, 3], [7, 1]]);
});
