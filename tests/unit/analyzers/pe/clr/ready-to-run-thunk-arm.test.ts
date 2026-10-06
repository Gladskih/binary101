import assert from "node:assert/strict";
import test from "node:test";
import { readArmReadyToRunThunk } from "../../../../../analyzers/pe/clr/ready-to-run-thunk-arm.js";
import { armEagerThunkCode, armLazyThunkCode, armDelayThunkCode, armAbsoluteThunkCode } from
  "../../../../helpers/ready-to-run-arm-thunk-fixture.js";

void test("decodes eager, lazy and delay-load Thumb2 stubs with PC-relative data cells", () => {
  assert.deepEqual(readArmReadyToRunThunk(armEagerThunkCode(), 0x100),
    { rva: 0x100, size: 16, kind: "eager", helperCellRva: 0x3000 });
  assert.deepEqual(readArmReadyToRunThunk(armLazyThunkCode(), 0x100),
    { rva: 0x100, size: 28, kind: "lazy", helperCellRva: 0x3000, moduleCellRva: 0x2000 });
  assert.deepEqual(readArmReadyToRunThunk(armDelayThunkCode(255), 0x100),
    { rva: 0x100, size: 40, kind: "delay-load family", helperCellRva: 0x3000,
      moduleCellRva: 0x2000, importSectionIndex: 255 });
  assert.equal(readArmReadyToRunThunk(armEagerThunkCode(0x80), 0x100)?.helperCellRva, 0x80);
});

void test("legacy pointers support all body shapes and exact unsigned RVA boundaries", () => {
  assert.deepEqual(readArmReadyToRunThunk(armAbsoluteThunkCode("lazy"), 0x100, 0x400000n),
    { rva: 0x100, size: 24, kind: "lazy", helperCellRva: 0x3000, moduleCellRva: 0x2000 });
  assert.deepEqual(readArmReadyToRunThunk(armAbsoluteThunkCode("delay-load family"), 0x100, 0x400000n),
    { rva: 0x100, size: 36, kind: "delay-load family", helperCellRva: 0x3000,
      moduleCellRva: 0x2000, importSectionIndex: 3 });
  assert.equal(readArmReadyToRunThunk(armAbsoluteThunkCode("eager", 0), 0x100)?.helperCellRva, 0);
  assert.equal(readArmReadyToRunThunk(armAbsoluteThunkCode("eager", 0), 0x100, 1n)?.helperCellRva, null);
  assert.equal(readArmReadyToRunThunk(armAbsoluteThunkCode("eager", 0), 0x100, -0x100000000n)?.helperCellRva, null);
});

void test("corrupt module MOVs and overflowing PC-relative cells are rejected or unresolved", () => {
  const wrongModule = armLazyThunkCode();
  wrongModule.setUint16(0, 0, true);

  assert.equal(readArmReadyToRunThunk(wrongModule, 0x100), null);
  assert.equal(readArmReadyToRunThunk(armEagerThunkCode(-1), 0x100)?.helperCellRva, null);
  assert.equal(readArmReadyToRunThunk(armDelayThunkCode(), 0xffffff00)?.moduleCellRva, null);
});

const rejectChangedWord = (view: DataView, offset: number): void => {
  view.setUint16(offset, 0, true);
  assert.equal(readArmReadyToRunThunk(view, 0x100, 0x400000n), null);
};

void test("requires complete modern and legacy instruction templates", () => {
  rejectChangedWord(armDelayThunkCode(), 0);
  rejectChangedWord(armAbsoluteThunkCode("eager"), 12);
  rejectChangedWord(armAbsoluteThunkCode("lazy"), 22);
  rejectChangedWord(armAbsoluteThunkCode("delay-load family"), 34);
});

void test("rejects truncated bodies, unaligned code and changed register/address instructions", () => {
  const wrongRegister = armEagerThunkCode();
  wrongRegister.setUint16(2, 0x0100, true);
  const wrongAdd = armEagerThunkCode();
  wrongAdd.setUint16(8, 0x44fb, true);

  assert.equal(readArmReadyToRunThunk(new DataView(new ArrayBuffer(0)), 0x100), null);
  assert.equal(readArmReadyToRunThunk(new DataView(armLazyThunkCode().buffer, 0, 27), 0x100), null);
  assert.equal(readArmReadyToRunThunk(armEagerThunkCode(), 0x101), null);
  assert.equal(readArmReadyToRunThunk(wrongRegister, 0x100), null);
  assert.equal(readArmReadyToRunThunk(wrongAdd, 0x100), null);
  assert.equal(readArmReadyToRunThunk(armEagerThunkCode(), -2), null);
});

void test("marks an overflowing cell RVA unresolved while retaining its code template", () => {
  assert.equal(readArmReadyToRunThunk(armEagerThunkCode(), 0xffffff00)?.helperCellRva, null);
});

void test("supports legacy absolute MOVW/MOVT pointers from .NET 8 Linux ARM images", () => {
  // System.Collections.dll 8.0.0, ARMEmitter uses IMAGE_REL_BASED_THUMB_MOV32.
  const bytes = Uint8Array.from(Buffer.from("4ff2882cc0f2450cdcf800c06047", "hex"));

  assert.deepEqual(readArmReadyToRunThunk(new DataView(bytes.buffer), 0x29ee8, 0x400000n),
    { rva: 0x29ee8, size: 14, kind: "eager", helperCellRva: 0x5f288 });
});
