"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { readTlsCallbacks } from "../../../../../analyzers/pe/directories/tls-callbacks.js";
import { MockFile } from "../../../../helpers/mock-file.js";
import { createTlsMappingFixture } from "../../../../fixtures/pe-tls-mapping.js";

const readTable = async (pointerSize: 4 | 8, pointers: bigint[], imageBase: bigint) => {
  const fixture = createTlsMappingFixture(pointerSize);
  pointers.forEach((pointer, index) =>
    fixture.writePointer(fixture.tableRva + index * pointerSize, pointer)
  );
  const warnings: string[] = [];
  return {
    ...await readTlsCallbacks(new MockFile(fixture.bytes), rva => rva,
      imageBase + BigInt(fixture.tableRva), imageBase, pointerSize, warnings),
    warnings
  };
};

for (const pointerSize of [4, 8] as const) {
  void test(`TLS callbacks ${pointerSize}: preserves order and duplicates`, async () => {
    const result = await readTable(pointerSize, [0x402000n, 0x401000n, 0x402000n], 0x400000n);

    assert.deepEqual(result, { rvas: [0x2000, 0x1000, 0x2000], status: "complete", warnings: [] });
  });

  void test(`TLS callbacks ${pointerSize}: skips invalid VAs but marks the list incomplete`, async () => {
    const result = await readTable(pointerSize, [0x402000n, 1n, 0x401000n], 0x400000n);

    assert.deepEqual(result, {
      rvas: [0x2000, 0x1000], status: "incomplete",
      warnings: ["TLS callback pointer 0x1 is not a valid VA."]
    });
  });

  void test(`TLS callbacks ${pointerSize}: accepts a callback at the image base`, async () => {
    const result = await readTable(pointerSize, [0x400000n], 0x400000n);

    assert.deepEqual(result, { rvas: [0], status: "complete", warnings: [] });
  });

  void test(`TLS callbacks ${pointerSize}: rejects a table VA below the image base`, async () => {
    const warnings: string[] = [];

    const result = await readTlsCallbacks(new MockFile(new Uint8Array()), () => null,
      1n, 0x400000n, pointerSize, warnings);

    assert.deepEqual(result, { rvas: [], status: "incomplete" });
    assert.deepEqual(warnings, ["TLS AddressOfCallBacks pointer 0x1 is not a valid VA."]);
  });

  for (const offset of [null, -1, 0.5, Number.NaN, Number.POSITIVE_INFINITY, 512]) {
    void test(`TLS callbacks ${pointerSize}: rejects invalid mapped offset ${offset}`, async () => {
      const fixture = createTlsMappingFixture(pointerSize);
      const warnings: string[] = [];

      const result = await readTlsCallbacks(new MockFile(fixture.bytes), () => offset,
        BigInt(fixture.tableRva), 0n, pointerSize, warnings);

      assert.deepEqual(result, { rvas: [], status: "incomplete" });
      assert.deepEqual(warnings,
        ["TLS callback table is truncated or unmapped before the null terminator."]);
    });
  }

  void test(`TLS callbacks ${pointerSize}: tolerates a short read despite advertised file size`, async () => {
    const fixture = createTlsMappingFixture(pointerSize);
    const warnings: string[] = [];
    const reader = new MockFile(fixture.bytes);
    reader.read = async () => new DataView(new ArrayBuffer(pointerSize - 1));

    const result = await readTlsCallbacks(reader, rva => rva,
      BigInt(fixture.tableRva), 0n, pointerSize, warnings);

    assert.deepEqual(result, { rvas: [], status: "incomplete" });
    assert.deepEqual(warnings,
      ["TLS callback table is truncated or unmapped before the null terminator."]);
  });

  void test(`TLS callbacks ${pointerSize}: accepts the null terminator at the RVA limit`, async () => {
    const fixture = createTlsMappingFixture(pointerSize);
    const warnings: string[] = [];
    // PE RVAs are DWORDs; a complete pointer may end exactly at 2^32.
    const lastPointerRva = 0x100000000 - pointerSize;

    const result = await readTlsCallbacks(new MockFile(fixture.bytes),
      rva => fixture.tableRva + rva - lastPointerRva,
      BigInt(lastPointerRva), 0n, pointerSize, warnings);

    assert.deepEqual(result, { rvas: [], status: "complete" });
    assert.deepEqual(warnings, []);
  });
}

void test("TLS callbacks 64: preserves VA precision beyond Number.MAX_SAFE_INTEGER", async () => {
  // 2^53 + 1 cannot be represented exactly by a JavaScript number.
  const result = await readTable(8, [0x20000000000001n, 0x200000ffffffffn], 0x20000000000001n);

  assert.deepEqual(result, { rvas: [0, 0xfffffffe], status: "complete", warnings: [] });
});

void test("TLS callbacks 64: rejects callback deltas outside the DWORD RVA range", async () => {
  const result = await readTable(8, [0x100000000n], 0n);

  assert.deepEqual(result, {
    rvas: [], status: "incomplete",
    warnings: ["TLS callback pointer 0x100000000 is not a valid VA."]
  });
});
