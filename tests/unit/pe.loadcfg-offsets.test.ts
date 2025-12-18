"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { parseLoadConfigDirectory } from "../../analyzers/pe/load-config.js";
import { MockFile } from "../helpers/mock-file.js";
import { expectDefined } from "../helpers/expect-defined.js";

void test("parseLoadConfigDirectory uses official field offsets (32-bit)", async () => {
  const bytes = new Uint8Array(512).fill(0);
  const dv = new DataView(bytes.buffer);
  const lcRva = 0x80;

  dv.setUint32(lcRva + 0x00, 0xc0, true); // Size
  dv.setUint32(lcRva + 0x04, 0x12345678, true); // TimeDateStamp
  dv.setUint16(lcRva + 0x08, 5, true); // MajorVersion
  dv.setUint16(lcRva + 0x0a, 1, true); // MinorVersion

  dv.setUint32(lcRva + 0x3c, 0xcafebabe, true); // SecurityCookie
  dv.setUint32(lcRva + 0x40, 0x200, true); // SEHandlerTable
  dv.setUint32(lcRva + 0x44, 3, true); // SEHandlerCount
  dv.setUint32(lcRva + 0x50, 0x300, true); // GuardCFFunctionTable
  dv.setUint32(lcRva + 0x54, 2, true); // GuardCFFunctionCount
  dv.setUint32(lcRva + 0x58, 0x1111, true); // GuardFlags

  const lc = expectDefined(
    await parseLoadConfigDirectory(
      new MockFile(bytes, "loadcfg32.bin"),
      [{ name: "LOAD_CONFIG", rva: lcRva, size: 0xc0 }],
      value => value,
      () => {},
      false
    )
  );

  assert.equal(lc.SecurityCookie, 0xcafebabe);
  assert.equal(lc.SEHandlerCount, 3);
  assert.equal(lc.GuardCFFunctionCount, 2);
  assert.equal(lc.GuardFlags, 0x1111);
});

void test("parseLoadConfigDirectory uses official field offsets (64-bit)", async () => {
  const bytes = new Uint8Array(512).fill(0);
  const dv = new DataView(bytes.buffer);

  dv.setUint32(0x00, 0x140, true); // Size
  dv.setUint32(0x04, 0x9abcdef0, true); // TimeDateStamp
  dv.setUint16(0x08, 10, true); // MajorVersion
  dv.setUint16(0x0a, 2, true); // MinorVersion

  dv.setBigUint64(0x58, 0x1234n, true); // SecurityCookie
  dv.setBigUint64(0x60, 0x5678n, true); // SEHandlerTable
  dv.setBigUint64(0x68, 5n, true); // SEHandlerCount
  dv.setBigUint64(0x80, 0x9abcn, true); // GuardCFFunctionTable
  dv.setBigUint64(0x88, 6n, true); // GuardCFFunctionCount
  dv.setUint32(0x90, 0xbeef, true); // GuardFlags

  const lc = expectDefined(
    await parseLoadConfigDirectory(
      new MockFile(bytes, "loadcfg64.bin"),
      [{ name: "LOAD_CONFIG", rva: 0x10, size: 0x140 }],
      value => (value === 0x10 ? 0 : value),
      () => {},
      true
    )
  );

  assert.equal(lc.SEHandlerCount, 5);
  assert.equal(lc.GuardCFFunctionCount, 6);
  assert.equal(lc.GuardFlags, 0xbeef);
});
