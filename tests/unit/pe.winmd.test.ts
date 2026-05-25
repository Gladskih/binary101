"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { detectPeSubtypeFromClr, isPeWinmd } from "../../analyzers/pe/winmd.js";
import type { PeClrHeader } from "../../analyzers/pe/clr/types.js";

const createClrWithVersion = (version: string | undefined): PeClrHeader => ({
  cb: 0,
  MajorRuntimeVersion: 0,
  MinorRuntimeVersion: 0,
  MetaDataRVA: 0,
  MetaDataSize: 0,
  Flags: 0,
  EntryPointToken: 0,
  ResourcesRVA: 0,
  ResourcesSize: 0,
  StrongNameSignatureRVA: 0,
  StrongNameSignatureSize: 0,
  CodeManagerTableRVA: 0,
  CodeManagerTableSize: 0,
  VTableFixupsRVA: 0,
  VTableFixupsSize: 0,
  ExportAddressTableJumpsRVA: 0,
  ExportAddressTableJumpsSize: 0,
  ManagedNativeHeaderRVA: 0,
  ManagedNativeHeaderSize: 0,
  ...(version ? { meta: { version, streams: [] } } : {})
});

void test("detectPeSubtypeFromClr recognises WinMD metadata version tokens", () => {
  assert.equal(detectPeSubtypeFromClr(createClrWithVersion("WindowsRuntime 1.2")), "winmd");
  assert.equal(detectPeSubtypeFromClr(createClrWithVersion("Windows Runtime 1.2")), "winmd");
});

void test("detectPeSubtypeFromClr does not infer WinMD without the required marker", () => {
  assert.equal(detectPeSubtypeFromClr(createClrWithVersion("v4.0.30319")), null);
  assert.equal(detectPeSubtypeFromClr(createClrWithVersion(undefined)), null);
  assert.equal(detectPeSubtypeFromClr(null), null);
});

void test("isPeWinmd checks the parsed PE subtype field", () => {
  assert.equal(isPeWinmd({ subtype: "winmd" }), true);
  assert.equal(isPeWinmd({}), false);
});
