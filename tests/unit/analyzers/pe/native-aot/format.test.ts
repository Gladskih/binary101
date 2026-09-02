"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import {
  isSupportedNativeAotSectionType,
  nativeAotSectionName
} from "../../../../../analyzers/pe/native-aot/format.js";

void test("NativeAOT section IDs stay within documented ranges", () => {
  assert.equal(isSupportedNativeAotSectionType(123), false);
  assert.equal(isSupportedNativeAotSectionType(124), true);
  assert.equal(isSupportedNativeAotSectionType(126), true);
  assert.equal(isSupportedNativeAotSectionType(127), false);
  assert.equal(isSupportedNativeAotSectionType(200), true);
  assert.equal(isSupportedNativeAotSectionType(215), true);
  assert.equal(isSupportedNativeAotSectionType(216), false);
  assert.equal(isSupportedNativeAotSectionType(300), true);
  assert.equal(isSupportedNativeAotSectionType(399), true);
  assert.equal(isSupportedNativeAotSectionType(400), false);
});

void test("nativeAotSectionName labels known sections and reserved IDs", () => {
  assert.deepEqual(
    [124, 125, 126, 200, 201, 202, 204, 205, 206, 207, 208, 209, 210, 212, 213, 214, 215, 313]
      .map(nativeAotSectionName),
    [
      "External type maps",
      "Proxy type maps",
      "Type-map assembly targets",
      "String table",
      "GC static region",
      "Thread-static region",
      "Type-manager indirection",
      "Eager class constructors",
      "Frozen-object region",
      "Dehydrated data",
      "Thread-static offsets",
      "Interface dispatch-cell info",
      "Interface dispatch cells",
      "Import address tables",
      "Module initializers",
      "GVM dispatch-cell info",
      "GVM dispatch cells",
      "Embedded reflection metadata"
    ]
  );
  assert.equal(nativeAotSectionName(300), "NativeAOT blob 0");
  assert.equal(nativeAotSectionName(314), "NativeAOT blob 14");
  assert.equal(nativeAotSectionName(203), "NativeAOT section 203");
});
