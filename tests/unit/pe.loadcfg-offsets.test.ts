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

  dv.setUint32(lcRva + 0x00, 0xc4, true); // Size
  dv.setUint32(lcRva + 0x04, 0x12345678, true); // TimeDateStamp
  dv.setUint16(lcRva + 0x08, 5, true); // MajorVersion
  dv.setUint16(lcRva + 0x0a, 1, true); // MinorVersion

  dv.setUint32(lcRva + 0x0c, 0x11111111, true); // GlobalFlagsClear
  dv.setUint32(lcRva + 0x10, 0x22222222, true); // GlobalFlagsSet
  dv.setUint32(lcRva + 0x14, 0x33333333, true); // CriticalSectionDefaultTimeout
  dv.setUint32(lcRva + 0x18, 0x44444444, true); // DeCommitFreeBlockThreshold
  dv.setUint32(lcRva + 0x1c, 0x55555555, true); // DeCommitTotalFreeThreshold
  dv.setUint32(lcRva + 0x20, 0x66666666, true); // LockPrefixTable
  dv.setUint32(lcRva + 0x24, 0x77777777, true); // MaximumAllocationSize
  dv.setUint32(lcRva + 0x28, 0x88888888, true); // VirtualMemoryThreshold
  dv.setUint32(lcRva + 0x2c, 0x99999999, true); // ProcessHeapFlags
  dv.setUint32(lcRva + 0x30, 0xaaaaaaaa, true); // ProcessAffinityMask
  dv.setUint16(lcRva + 0x34, 0xbbbb, true); // CSDVersion
  dv.setUint16(lcRva + 0x36, 0xcccc, true); // DependentLoadFlags
  dv.setUint32(lcRva + 0x38, 0xdddddddd, true); // EditList
  dv.setUint32(lcRva + 0x3c, 0xcafebabe, true); // SecurityCookie
  dv.setUint32(lcRva + 0x40, 0x200, true); // SEHandlerTable
  dv.setUint32(lcRva + 0x44, 3, true); // SEHandlerCount
  dv.setUint32(lcRva + 0x50, 0x300, true); // GuardCFFunctionTable
  dv.setUint32(lcRva + 0x54, 2, true); // GuardCFFunctionCount
  dv.setUint32(lcRva + 0x58, 0x1111, true); // GuardFlags
  dv.setUint16(lcRva + 0x5c, 0x0102, true); // CodeIntegrity.Flags
  dv.setUint16(lcRva + 0x5e, 0x0304, true); // CodeIntegrity.Catalog
  dv.setUint32(lcRva + 0x60, 0x05060708, true); // CodeIntegrity.CatalogOffset
  dv.setUint32(lcRva + 0x64, 0x090a0b0c, true); // CodeIntegrity.Reserved
  dv.setUint32(lcRva + 0xa0, 0x13579bdf, true); // VolatileMetadataPointer
  dv.setUint32(lcRva + 0xb8, 0x2468ace0, true); // CastGuardOsDeterminedFailureMode
  dv.setUint32(lcRva + 0xbc, 0xdeadbeef, true); // GuardMemcpyFunctionPointer
  dv.setUint32(lcRva + 0xc0, 0x01020304, true); // UmaFunctionPointers

  const lc = expectDefined(
    await parseLoadConfigDirectory(
      new MockFile(bytes, "loadcfg32.bin"),
      [{ name: "LOAD_CONFIG", rva: lcRva, size: 0xc4 }],
      value => value,
      () => {},
      false
    )
  );

  assert.equal(lc.GlobalFlagsClear, 0x11111111);
  assert.equal(lc.ProcessHeapFlags, 0x99999999);
  assert.equal(lc.CSDVersion, 0xbbbb);
  assert.equal(lc.DependentLoadFlags, 0xcccc);
  assert.equal(lc.SecurityCookie, 0xcafebabe);
  assert.equal(lc.SEHandlerCount, 3);
  assert.equal(lc.GuardCFFunctionCount, 2);
  assert.equal(lc.GuardFlags, 0x1111);
  assert.equal(lc.CodeIntegrity.Flags, 0x0102);
  assert.equal(lc.CodeIntegrity.Catalog, 0x0304);
  assert.equal(lc.VolatileMetadataPointer, 0x13579bdf);
  assert.equal(lc.CastGuardOsDeterminedFailureMode, 0x2468ace0);
  assert.equal(lc.GuardMemcpyFunctionPointer, 0xdeadbeef);
  assert.equal(lc.UmaFunctionPointers, 0x01020304);
});

void test("parseLoadConfigDirectory uses official field offsets (64-bit)", async () => {
  const bytes = new Uint8Array(512).fill(0);
  const dv = new DataView(bytes.buffer);

  dv.setUint32(0x00, 0x148, true); // Size
  dv.setUint32(0x04, 0x9abcdef0, true); // TimeDateStamp
  dv.setUint16(0x08, 10, true); // MajorVersion
  dv.setUint16(0x0a, 2, true); // MinorVersion

  dv.setUint32(0x0c, 0x11111111, true); // GlobalFlagsClear
  dv.setBigUint64(0x18, 0x22222222n, true); // DeCommitFreeBlockThreshold
  dv.setBigUint64(0x58, 0x1234n, true); // SecurityCookie
  dv.setBigUint64(0x60, 0x5678n, true); // SEHandlerTable
  dv.setBigUint64(0x68, 5n, true); // SEHandlerCount
  dv.setBigUint64(0x80, 0x9abcn, true); // GuardCFFunctionTable
  dv.setBigUint64(0x88, 6n, true); // GuardCFFunctionCount
  dv.setUint32(0x90, 0xbeef, true); // GuardFlags
  dv.setUint16(0x94, 0x0102, true); // CodeIntegrity.Flags
  dv.setBigUint64(0x100, 0xabcdefn, true); // VolatileMetadataPointer
  dv.setBigUint64(0x130, 0x13579bdfn, true); // CastGuardOsDeterminedFailureMode
  dv.setBigUint64(0x140, 0x0102030405060708n, true); // UmaFunctionPointers

  const lc = expectDefined(
    await parseLoadConfigDirectory(
      new MockFile(bytes, "loadcfg64.bin"),
      [{ name: "LOAD_CONFIG", rva: 0x10, size: 0x148 }],
      value => (value === 0x10 ? 0 : value),
      () => {},
      true
    )
  );

  assert.equal(lc.GlobalFlagsClear, 0x11111111);
  assert.equal(lc.DeCommitFreeBlockThreshold, 0x22222222);
  assert.equal(lc.SEHandlerCount, 5);
  assert.equal(lc.GuardCFFunctionCount, 6);
  assert.equal(lc.GuardFlags, 0xbeef);
  assert.equal(lc.CodeIntegrity.Flags, 0x0102);
  assert.equal(lc.VolatileMetadataPointer, 0xabcdef);
  assert.equal(lc.CastGuardOsDeterminedFailureMode, 0x13579bdf);
  assert.equal(lc.UmaFunctionPointers, 0);
});
