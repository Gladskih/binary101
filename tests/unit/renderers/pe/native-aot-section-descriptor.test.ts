"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { getNativeAotSectionDescriptor } from
  "../../../../renderers/pe/native-aot-section-descriptor.js";

void test("getNativeAotSectionDescriptor distinguishes confirmed metadata", () => {
  const candidate = getNativeAotSectionDescriptor(null);
  const confirmed = getNativeAotSectionDescriptor({
    status: "confirmed",
    layout: "nativeaot-readytorun-size-pointer-v1",
    modulePointerRva: 0x1000,
    headerRva: 0x1100,
    majorVersion: 27,
    minorVersion: 1,
    sections: [{ type: 313, rva: 0x1200, size: 4 }]
  });

  assert.deepEqual(candidate, {
    key: "native-aot",
    summary: "conservative evidence",
    title: "Native AOT candidate"
  });
  assert.deepEqual(confirmed, {
    key: "native-aot",
    summary: "1 section",
    title: "NativeAOT metadata"
  });
});
