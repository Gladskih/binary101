import assert from "node:assert/strict";
import { test } from "node:test";
import { analyzePeAppHost } from "../../../../../analyzers/pe/apphost/index.js";
import {
  createPeAppHostFixture, refreshPeAppHostFixture
} from "../../../../fixtures/pe-apphost-fixture.js";

const sectionStartBinding = (path: string) => {
  const fixture = createPeAppHostFixture();
  // Move the synthetic locator past the maximum-length path; none of these offsets
  // is prescribed by PE or apphost. Keep both objects inside the writable section.
  fixture.bytes.copyWithin(0x600, 0x148, 0x170);
  fixture.bytes.fill(0, fixture.section.pointerToRawData, 0x600);
  fixture.bytes.set(new TextEncoder().encode(`${path}\0`), fixture.section.pointerToRawData);
  refreshPeAppHostFixture(fixture);
  return fixture;
};

void test("apphost accepts a path starting at the first byte of a section", async () => {
  const fixture = sectionStartBinding("Boundary.dll");

  const result = await analyzePeAppHost(fixture.file, fixture.reader, [fixture.section]);

  assert.deepEqual(result?.bindings, [{
    rva: fixture.section.virtualAddress, kind: "managed-assembly", value: "Boundary.dll"
  }]);
});

for (const smallerExtent of ["virtualSize", "sizeOfRawData"] as const) {
  void test(`apphost respects the smaller ${smallerExtent} section extent`, async () => {
    const fixture = createPeAppHostFixture();
    // Synthetic extent ends after the locator but before the path at section +0x180.
    // PE section extents: https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#section-table-section-headers
    fixture.section[smallerExtent] = 0x100;

    const result = await analyzePeAppHost(fixture.file, fixture.reader, [fixture.section]);

    assert.equal(result?.locators.length, 1);
    assert.deepEqual(result?.bindings, []);
    assert.deepEqual(result?.issues, ["The embedded managed application path was not found."]);
  });
}

for (const [length, count] of [[1024, 1], [1025, 0]] as const) {
  void test(`apphost checks a ${length}-byte path at the section start`, async () => {
    // apphost.c EMBED_MAX: 1024 UTF-8 bytes excluding NUL; ".dll" uses four bytes.
    const path = `${"a".repeat(length - 4)}.dll`;
    const fixture = sectionStartBinding(path);

    const result = await analyzePeAppHost(fixture.file, fixture.reader, [fixture.section]);

    assert.equal(result?.bindings.length, count);
  });
}

void test("apphost rejects a binding read missing only its final NUL", async () => {
  const fixture = createPeAppHostFixture();
  const reader = { ...fixture.reader, readBytes: (offset: number, size: number) =>
    fixture.reader.readBytes(offset, size - 1) };

  const result = await analyzePeAppHost(fixture.file, reader, [fixture.section]);

  assert.deepEqual(result?.bindings, []);
});

void test("apphost rechecks the suffix when reading a scanned binding", async () => {
  const fixture = createPeAppHostFixture();
  const reader = { ...fixture.reader, readBytes: async (offset: number, size: number) => {
    const bytes = (await fixture.reader.readBytes(offset, size)).slice();
    bytes.set(new TextEncoder().encode(".exe\0"), bytes.length - 5);
    return bytes;
  } };

  const result = await analyzePeAppHost(fixture.file, reader, [fixture.section]);

  assert.deepEqual(result?.bindings, []);
});

// Negative, exact EOF, and larger than Number.MAX_SAFE_INTEGER. The last case uses
// a synthetic reader size above that bound to isolate the safe-integer check.
for (const [offset, fileSize] of [
  [-1n, 0x1000], [0x1000n, 0x1000], [0x20000000000000n, 0x40000000000000]
] as const) {
  void test(`apphost never reads a header at invalid offset ${offset}`, async () => {
    const fixture = createPeAppHostFixture(offset);
    const reads: number[] = [];
    const reader = { ...fixture.reader,
      size: fileSize,
      read: async (position: number, size: number) => {
        reads.push(position);
        return fixture.reader.read(position, size);
      }
    };

    const result = await analyzePeAppHost(fixture.file, reader, [fixture.section]);

    // Only the packed locator is read; the rejected header causes no I/O.
    assert.deepEqual(reads, [0x148]);
    assert.deepEqual(result?.issues, [".NET apphost bundle header offset points outside the file."]);
  });
}

void test("apphost accepts the largest exactly representable header offset", async () => {
  const fixture = createPeAppHostFixture(BigInt(Number.MAX_SAFE_INTEGER));
  const reads: number[] = [];
  const reader = { ...fixture.reader, size: Number.MAX_SAFE_INTEGER + 1,
    read: async (position: number, size: number) => {
      reads.push(position);
      return fixture.reader.read(position, size);
    }
  };

  const result = await analyzePeAppHost(fixture.file, reader, [fixture.section]);

  assert.deepEqual(reads, [0x148, Number.MAX_SAFE_INTEGER]);
  assert.deepEqual(result?.issues,
    ["Single-file bundle header is truncated before its bundle ID."]);
});

void test("apphost forwards malformed bundle-header warnings", async () => {
  // The fixture leaves zero bytes at this valid in-file header address.
  const fixture = createPeAppHostFixture(0x800n);

  const result = await analyzePeAppHost(fixture.file, fixture.reader, [fixture.section]);

  assert.deepEqual(result?.issues, ["Single-file bundle ID has an invalid length encoding."]);
});

void test("apphost forwards scanner candidate-budget warnings", async () => {
  // Seventy strings exceed the scanner's resource budget of 64 candidates.
  const fixture = createPeAppHostFixture(0n, "noise.dll\0".repeat(70));

  const result = await analyzePeAppHost(fixture.file, fixture.reader, [fixture.section]);

  assert.ok(result?.issues.includes(".NET apphost candidate limit reached; results are incomplete."));
});
