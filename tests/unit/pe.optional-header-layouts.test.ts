"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { parseOptionalHeaderTail64 } from "../../analyzers/pe/optional-header-layouts.js";

// 2^53 + 1 is the first unsigned integer JS cannot represent exactly as Number.
const FIRST_UNSAFE_U64 = (1n << 53n) + 1n;
const unsafeU64At = (step: bigint): bigint => FIRST_UNSAFE_U64 + step * 2n;

const createOptionalHeaderTail64View = (): DataView => {
  const bytes = new Uint8Array(0x58);
  const view = new DataView(bytes.buffer);
  const writeU32 = (offset: number, value: number): void => view.setUint32(offset, value, true);
  const writeU64 = (offset: number, value: bigint): void => view.setBigUint64(offset, value, true);

  writeU64(0x00, unsafeU64At(0n));
  writeU32(0x08, 0x1000);
  writeU32(0x0c, 0x200);
  writeU32(0x20, 0x3000);
  writeU32(0x24, 0x200);
  writeU64(0x30, unsafeU64At(1n));
  writeU64(0x38, unsafeU64At(2n));
  writeU64(0x40, unsafeU64At(3n));
  writeU64(0x48, unsafeU64At(4n));
  writeU32(0x54, 16);

  return view;
};

void test("parseOptionalHeaderTail64 preserves 64-bit values beyond Number.MAX_SAFE_INTEGER", () => {
  const parsed = parseOptionalHeaderTail64(createOptionalHeaderTail64View(), 0);

  assert.strictEqual(BigInt(parsed.ImageBase), unsafeU64At(0n), "ImageBase");
  assert.strictEqual(BigInt(parsed.SizeOfStackReserve), unsafeU64At(1n), "SizeOfStackReserve");
  assert.strictEqual(BigInt(parsed.SizeOfStackCommit), unsafeU64At(2n), "SizeOfStackCommit");
  assert.strictEqual(BigInt(parsed.SizeOfHeapReserve), unsafeU64At(3n), "SizeOfHeapReserve");
  assert.strictEqual(BigInt(parsed.SizeOfHeapCommit), unsafeU64At(4n), "SizeOfHeapCommit");
});
