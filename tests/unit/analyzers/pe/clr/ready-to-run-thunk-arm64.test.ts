import assert from "node:assert/strict";
import test from "node:test";
import { readArm64ReadyToRunThunk } from
  "../../../../../analyzers/pe/clr/ready-to-run-thunk-arm64.js";
import { arm64ThunkCode } from "../../../../helpers/ready-to-run-arm64-thunk-fixture.js";

void test("decodes ARM64 code and its relocated inline pointer literals", () => {
  assert.deepEqual(readArm64ReadyToRunThunk(arm64ThunkCode(), 0x1000, 0x140000000n),
    { rva: 0x1000, size: 20, kind: "eager", helperCellRva: 0x3000 });
  assert.deepEqual(readArm64ReadyToRunThunk(arm64ThunkCode([0x580000e1, 0xf9400021]), 0x1000, 0x140000000n),
    { rva: 0x1000, size: 36, kind: "lazy", helperCellRva: 0x3000, moduleCellRva: 0x2000 });
  // MOVZ X9,#65535 encodes a full ushort table index.
  assert.deepEqual(readArm64ReadyToRunThunk(arm64ThunkCode([0xd29fffe9, 0x580000ea, 0xf940014a]),
    0x1000, 0x140000000n), { rva: 0x1000, size: 40, kind: "delay-load family",
    helperCellRva: 0x3000, moduleCellRva: 0x2000, importSectionIndex: 65535 });
});

void test("rejects incomplete bodies and validates the whole branch sequence", () => {
  const short = arm64ThunkCode();
  const wrong = arm64ThunkCode();
  wrong.setUint32(8, 0xd61f0160, true);

  assert.equal(readArm64ReadyToRunThunk(new DataView(new ArrayBuffer(0)), 0x1000, 0n), null);
  assert.equal(readArm64ReadyToRunThunk(new DataView(short.buffer, 0, 19), 0x1000, 0n), null);
  assert.equal(readArm64ReadyToRunThunk(wrong, 0x1000, 0n), null);
  assert.equal(readArm64ReadyToRunThunk(arm64ThunkCode([0xd2800009, 0x580000eb, 0xf940014a]),
    0x1000, 0n), null);
  assert.equal(readArm64ReadyToRunThunk(arm64ThunkCode([0x580000e1, 0xf9400020]), 0x1000, 0n), null);
});

void test("does not convert out-of-image literal pointers to RVAs", () => {
  assert.equal(readArm64ReadyToRunThunk(arm64ThunkCode([], 0n), 0x1000, 0n)?.helperCellRva, 0);
  assert.equal(readArm64ReadyToRunThunk(arm64ThunkCode([], 0n), 0x1000, 1n)?.helperCellRva, null);
  assert.equal(readArm64ReadyToRunThunk(arm64ThunkCode([], 0x100000000n), 0x1000, 0n)?.helperCellRva, null);
});

void test("rejects unaligned and overflowing code ranges and partially truncated prefixes", () => {
  const lazy = arm64ThunkCode([0x580000e1, 0xf9400021]);
  const delay = arm64ThunkCode([0xd2800009, 0x580000ea, 0xf940014a]);
  const wrongIndexRegister = arm64ThunkCode([0xd2800008, 0x580000ea, 0xf940014a]);

  assert.equal(readArm64ReadyToRunThunk(arm64ThunkCode(), 0x1001, 0n), null);
  assert.equal(readArm64ReadyToRunThunk(arm64ThunkCode(), 0xfffffff0, 0n), null);
  assert.equal(readArm64ReadyToRunThunk(new DataView(lazy.buffer, 0, 35), 0x1000, 0n), null);
  assert.equal(readArm64ReadyToRunThunk(new DataView(delay.buffer, 0, 39), 0x1000, 0n), null);
  assert.equal(readArm64ReadyToRunThunk(wrongIndexRegister, 0x1000, 0n), null);
});
