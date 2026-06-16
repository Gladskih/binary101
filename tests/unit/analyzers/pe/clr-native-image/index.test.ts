"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import {
  detectPeClrNativeImageSubtypeFromClr,
  isPeClrNativeImage
} from "../../../../../analyzers/pe/clr-native-image.js";
import type { PeClrHeader } from "../../../../../analyzers/pe/clr/types.js";

const createClrWithManagedNativeHeader = (
  status: NonNullable<PeClrHeader["readyToRun"]>["status"]
): PeClrHeader => ({
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
  readyToRun: {
    status,
    signature: null,
    majorVersion: null,
    minorVersion: null,
    flags: null,
    sectionCount: 0,
    sections: [],
    issues: []
  }
});

void test("detectPeClrNativeImageSubtypeFromClr recognises confirmed CLR native images", () => {
  assert.equal(detectPeClrNativeImageSubtypeFromClr(createClrWithManagedNativeHeader("ready-to-run")), "clr-native-image");
  assert.equal(detectPeClrNativeImageSubtypeFromClr(createClrWithManagedNativeHeader("ngen")), "clr-native-image");
  assert.equal(
    detectPeClrNativeImageSubtypeFromClr(createClrWithManagedNativeHeader("unknown-managed-native-header")),
    "clr-native-image"
  );
});

void test("detectPeClrNativeImageSubtypeFromClr ignores unconfirmed managed native headers", () => {
  assert.equal(detectPeClrNativeImageSubtypeFromClr(createClrWithManagedNativeHeader("truncated")), null);
  assert.equal(detectPeClrNativeImageSubtypeFromClr(createClrWithManagedNativeHeader("unmapped")), null);
  assert.equal(detectPeClrNativeImageSubtypeFromClr(createClrWithManagedNativeHeader("absent")), null);
});

void test("isPeClrNativeImage checks the parsed PE subtype field", () => {
  assert.equal(isPeClrNativeImage({ subtype: "clr-native-image" }), true);
  assert.equal(isPeClrNativeImage({ subtype: "winmd" }), false);
  assert.equal(isPeClrNativeImage({}), false);
});
