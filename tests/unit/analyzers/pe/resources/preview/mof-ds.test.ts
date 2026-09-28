import assert from "node:assert/strict";
import { test } from "node:test";
import { decompressMofDs01 } from "../../../../../../analyzers/pe/resources/preview/mof-ds.js";
import { encodeDsLiterals, packDsCodes } from "../../../../../helpers/binary-mof-fixture.js";

void test("decompresses DS-01 literal bytes including high-bit characters", () => {
  const expected = Uint8Array.from([70, 79, 77, 66, 0xff]);
  const issues: string[] = [];
  assert.deepEqual(decompressMofDs01(encodeDsLiterals(expected), expected.length, issues),
    expected);
  assert.deepEqual(issues, []);
});

void test("decompresses a short backward reference", () => {
  // bmfdec.c: case 0 uses 6-bit offset; odd length code copies two bytes.
  const compressed = packDsCodes([
    { value: 0x5344, bits: 16 }, { value: 0x0100, bits: 16 },
    { value: (65 << 2) | 2, bits: 9 }, { value: 4, bits: 8 },
    { value: 1, bits: 1 }, { value: 7, bits: 3 }, { value: 4095, bits: 12 }
  ]);
  const issues: string[] = [];
  assert.deepEqual(decompressMofDs01(compressed, 3, issues),
    Uint8Array.from([65, 65, 65]));
  assert.deepEqual(issues, []);
});

void test("rejects invalid sizes and DS headers", () => {
  const bytes = encodeDsLiterals(Uint8Array.from([65]));
  for (const size of [-1, 1.5, Number.NaN, 32 * 1024 * 1024 + 1]) {
    const issues: string[] = [];
    assert.equal(decompressMofDs01(bytes, size, issues), null);
    assert.deepEqual(issues, ["Binary MOF decompressed size is invalid or too large."]);
  }
  const damaged = bytes.slice();
  damaged[0] = 0;
  const issues: string[] = [];
  assert.equal(decompressMofDs01(damaged, 1, issues), null);
  assert.deepEqual(issues, ["Binary MOF DS-01 header is invalid."]);
});

void test("accepts an empty DS-01 payload with a valid final marker", () => {
  const issues: string[] = [];
  assert.deepEqual(decompressMofDs01(encodeDsLiterals(new Uint8Array(0)), 0, issues),
    new Uint8Array(0));
  assert.deepEqual(issues, []);
});

void test("rejects truncated data, zero offsets and output overrun", () => {
  const literal = encodeDsLiterals(Uint8Array.from([65]));
  const truncated: string[] = [];
  assert.equal(decompressMofDs01(literal.subarray(0, 4), 1, truncated), null);
  assert.deepEqual(truncated, ["Binary MOF DS-01 stream is truncated or invalid."]);
  const badReference = packDsCodes([
    { value: 0x5344, bits: 16 }, { value: 0x0100, bits: 16 },
    { value: 0, bits: 8 }, { value: 1, bits: 1 }
  ]);
  const invalid: string[] = [];
  assert.equal(decompressMofDs01(badReference, 2, invalid), null);
  assert.deepEqual(invalid, ["Binary MOF DS-01 stream is truncated or invalid."]);
  const overrun: string[] = [];
  assert.equal(decompressMofDs01(encodeDsLiterals(Uint8Array.from([65])), 2, overrun), null);
  assert.deepEqual(overrun, ["Binary MOF DS-01 stream is truncated or invalid."]);
});

void test("checks the final DS synchronization marker", () => {
  const bytes = encodeDsLiterals(Uint8Array.from([65]));
  bytes[bytes.length - 1] = 0;
  const issues: string[] = [];
  assert.equal(decompressMofDs01(bytes, 1, issues), null);
  assert.deepEqual(issues, ["Binary MOF DS-01 final synchronization marker is invalid."]);
});

void test("rejects a wrong final synchronization prefix", () => {
  const bytes = packDsCodes([
    { value: 0x5344, bits: 16 }, { value: 0x0100, bits: 16 },
    { value: (65 << 2) | 2, bits: 9 },
    { value: 0, bits: 3 }, { value: 4095, bits: 12 }
  ]);
  const issues: string[] = [];
  assert.equal(decompressMofDs01(bytes, 1, issues), null);
  assert.deepEqual(issues, ["Binary MOF DS-01 final synchronization marker is invalid."]);
});

const repeatFixture = (
  seedLength: number, offsetCode: { value: number; bits: number },
  lengthCode: Array<{ value: number; bits: number }>
): Uint8Array => packDsCodes([
  { value: 0x5344, bits: 16 }, { value: 0x0100, bits: 16 },
  ...Array.from({ length: seedLength }, () => ({ value: (65 << 2) | 2, bits: 9 })),
  offsetCode, ...lengthCode, { value: 7, bits: 3 }, { value: 4095, bits: 12 }
]);

void test("decodes each DS-01 backward-reference length code", () => {
  // bmfdec.c decode_repeat_length uses a 1,3,...,15-bit prefix and a 17-bit long form.
  const codes = [
    { size: 3, bits: [{ value: 1, bits: 1 }] },
    { size: 4, bits: [{ value: 2, bits: 3 }] },
    { size: 6, bits: [{ value: 4, bits: 5 }] },
    { size: 10, bits: [{ value: 8, bits: 7 }] },
    { size: 18, bits: [{ value: 16, bits: 9 }] },
    { size: 34, bits: [{ value: 32, bits: 11 }] },
    { size: 66, bits: [{ value: 64, bits: 13 }] },
    { size: 130, bits: [{ value: 128, bits: 15 }] },
    { size: 258, bits: [{ value: 256, bits: 9 }, { value: 0, bits: 8 }] }
  ];
  for (const code of codes) {
    const issues: string[] = [];
    const input = repeatFixture(1, { value: 4, bits: 8 }, code.bits);
    assert.deepEqual(decompressMofDs01(input, code.size, issues),
      new Uint8Array(code.size).fill(65));
    assert.deepEqual(issues, []);
  }
});

void test("decodes medium and wide DS-01 backward offsets", () => {
  // bmfdec.c offsets use 11-bit codes from 64 and 15-bit codes from 320.
  const medium: string[] = [];
  const wide: string[] = [];
  assert.deepEqual(decompressMofDs01(repeatFixture(64,
    { value: 3, bits: 11 }, [{ value: 1, bits: 1 }]), 66, medium),
  new Uint8Array(66).fill(65));
  assert.deepEqual(decompressMofDs01(repeatFixture(320,
    { value: 7, bits: 15 }, [{ value: 1, bits: 1 }]), 322, wide),
  new Uint8Array(322).fill(65));
  assert.deepEqual(medium, []);
  assert.deepEqual(wide, []);
});

void test("accepts a DS-01 synchronization marker at a 512-byte boundary", () => {
  // bmfdec.c: the 0x113f offset is a marker only after each 512 output bytes.
  const input = packDsCodes([
    { value: 0x5344, bits: 16 }, { value: 0x0100, bits: 16 },
    ...Array.from({ length: 512 }, () => ({ value: (65 << 2) | 2, bits: 9 })),
    { value: 0x7fff, bits: 15 }, { value: (66 << 2) | 2, bits: 9 },
    { value: 7, bits: 3 }, { value: 4095, bits: 12 }
  ]);
  const issues: string[] = [];
  const expected = new Uint8Array(513).fill(65);
  expected[512] = 66;
  assert.deepEqual(decompressMofDs01(input, 513, issues), expected);
  assert.deepEqual(issues, []);
});

void test("continues decoding literals after a backward reference", () => {
  const input = packDsCodes([
    { value: 0x5344, bits: 16 }, { value: 0x0100, bits: 16 },
    { value: (65 << 2) | 2, bits: 9 }, { value: 4, bits: 8 },
    { value: 1, bits: 1 }, { value: (66 << 2) | 2, bits: 9 },
    { value: 7, bits: 3 }, { value: 4095, bits: 12 }
  ]);
  const issues: string[] = [];
  assert.deepEqual(decompressMofDs01(input, 4, issues), Uint8Array.from([65, 65, 65, 66]));
  assert.deepEqual(issues, []);
});

void test("rejects references before the start of decompressed data", () => {
  const issues: string[] = [];
  assert.equal(decompressMofDs01(repeatFixture(1,
    { value: 3, bits: 11 }, [{ value: 1, bits: 1 }]), 3, issues), null);
  assert.deepEqual(issues, ["Binary MOF DS-01 stream is truncated or invalid."]);
});

void test("treats synchronization codes as markers only at 512-byte boundaries", () => {
  const markerCase = (seedLength: number, offset: number): Uint8Array => packDsCodes([
    { value: 0x5344, bits: 16 }, { value: 0x0100, bits: 16 },
    ...Array.from({ length: seedLength }, () => ({ value: (65 << 2) | 2, bits: 9 })),
    { value: offset, bits: 15 }, { value: (66 << 2) | 2, bits: 9 },
    { value: 7, bits: 3 }, { value: 4095, bits: 12 }
  ]);
  const misplaced: string[] = [];
  const wrongOffset: string[] = [];
  assert.equal(decompressMofDs01(markerCase(1, 0x7fff), 2, misplaced), null);
  assert.equal(decompressMofDs01(markerCase(512, 0x7ff7), 513, wrongOffset), null);
  assert.match(misplaced.join(" "), /invalid/);
  assert.match(wrongOffset.join(" "), /invalid/);
});
