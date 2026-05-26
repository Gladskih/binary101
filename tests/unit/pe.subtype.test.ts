"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { detectPeSubtypeFromClr } from "../../analyzers/pe/subtype.js";
import type { PeClrHeader } from "../../analyzers/pe/clr/types.js";

const createClr = (values: Partial<PeClrHeader>): PeClrHeader => ({
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
  ...values
});

void test("detectPeSubtypeFromClr delegates to WinMD subtype detection first", () => {
  assert.equal(detectPeSubtypeFromClr(createClr({
    meta: { version: "WindowsRuntime 1.4", streams: [] }
  })), "winmd");
});

void test("detectPeSubtypeFromClr delegates to CLR native image detection", () => {
  assert.equal(detectPeSubtypeFromClr(createClr({
    readyToRun: {
      status: "unknown-managed-native-header",
      signature: null,
      majorVersion: null,
      minorVersion: null,
      flags: null,
      sectionCount: 0,
      sections: [],
      issues: []
    }
  })), "clr-native-image");
});

void test("detectPeSubtypeFromClr returns null without confirmed subtype markers", () => {
  assert.equal(detectPeSubtypeFromClr(createClr({})), null);
  assert.equal(detectPeSubtypeFromClr(null), null);
});
