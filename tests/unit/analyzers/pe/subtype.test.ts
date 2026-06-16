"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import {
  detectPeMuiResourceSubtype,
  detectPeSubtypeFromClr
} from "../../../../analyzers/pe/subtype.js";
import type { PeClrHeader } from "../../../../analyzers/pe/clr/types.js";
import type { MuiResourceConfiguration } from "../../../../analyzers/pe/resources/mui-config.js";

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

const createMuiResourceConfiguration = (): MuiResourceConfiguration => ({
  declaredSize: 0,
  version: 0x00010000,
  pathType: 0,
  fileType: 0x12,
  systemAttributes: 0,
  fallbackLocation: 0,
  serviceChecksum: "",
  checksum: "",
  unknown1: [0, 0],
  unknown2: [0, 0],
  muiPaths: [],
  mainTypeNames: ["MUI"],
  mainTypeIds: [24],
  muiTypeNames: [],
  muiTypeIds: [16],
  languageName: "en-US",
  fallbackLanguageName: null,
  trailingByteCount: 0
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

void test("detectPeMuiResourceSubtype recognizes resource-only MUI images", () => {
  assert.equal(
    detectPeMuiResourceSubtype(
      createMuiResourceConfiguration(),
      0,
      [{ characteristics: 0 }]
    ),
    "mui-resource-image"
  );
});

void test("detectPeMuiResourceSubtype ignores MUI configs on executable images", () => {
  assert.equal(
    detectPeMuiResourceSubtype(
      createMuiResourceConfiguration(),
      0x1000,
      [{ characteristics: 0 }]
    ),
    null
  );
  assert.equal(
    detectPeMuiResourceSubtype(
      createMuiResourceConfiguration(),
      0,
      // Microsoft PE format, "Section Flags": IMAGE_SCN_MEM_EXECUTE is 0x20000000.
      [{ characteristics: 0x20000000 }]
    ),
    null
  );
});
