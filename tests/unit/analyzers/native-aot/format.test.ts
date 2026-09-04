"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import {
  isSupportedNativeAotSectionType,
  nativeAotSectionName
} from "../../../../analyzers/native-aot/format.js";

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

void test("nativeAotSectionName labels every published reflection-map blob", () => {
  // ReflectionMapBlob IDs are offset by 300 in the ReadyToRun section table:
  // https://github.com/dotnet/runtime/blob/main/src/coreclr/tools/Common/Internal/Runtime/MetadataBlob.cs
  assert.deepEqual(
    [
      301, 302, 303, 304, 306, 307, 308, 309, 310, 311, 316, 317, 318, 319, 321,
      322, 324, 325, 326, 327, 328, 329, 330, 331, 332, 333, 334, 335, 336
    ].map(nativeAotSectionName),
    [
      "Type map",
      "Array map",
      "Pointer-type map",
      "Function-pointer-type map",
      "Invoke map",
      "Virtual-invoke map",
      "Common fixups table",
      "Field-access map",
      "Class-constructor context map",
      "By-reference-type map",
      "Struct marshalling-stub map",
      "Delegate marshalling-stub map",
      "Generic virtual-method table",
      "Interface generic virtual-method table",
      "Type-template map",
      "Generic-methods template map",
      "Resource index",
      "Resource data",
      "Stack-trace embedded metadata",
      "Stack-trace method-RVA-to-token map",
      "Stack-trace line numbers",
      "Stack-trace documents",
      "Native-layout info",
      "Native references",
      "Generics hash table",
      "Native statics",
      "Statics-info hash table",
      "Generic-methods hash table",
      "Exact-method-instantiations hash table"
    ]
  );
});
