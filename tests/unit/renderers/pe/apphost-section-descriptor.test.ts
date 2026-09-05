import assert from "node:assert/strict";
import { test } from "node:test";
import { getPeAppHostSectionDescriptor } from
  "../../../../renderers/pe/apphost-section-descriptor.js";

void test("apphost summary does not call an unavailable locator a bundle", () => {
  assert.equal(getPeAppHostSectionDescriptor({
    locators: [{ rva: 0, bundleHeaderOffset: null }], bindings: [], issues: []
  }).summary, "native .NET launcher");
});

void test("apphost summary detects a bundle among non-bundle locators", () => {
  assert.deepEqual(getPeAppHostSectionDescriptor({
    locators: [{ rva: 0, bundleHeaderOffset: 0n }, { rva: 1, bundleHeaderOffset: 1n }],
    bindings: [], issues: []
  }), { key: "apphost", summary: "single-file bundle", title: ".NET apphost" });
});

void test("apphost summary excludes negative offsets", () => {
  assert.equal(getPeAppHostSectionDescriptor({
    locators: [{ rva: 0, bundleHeaderOffset: -1n }], bindings: [], issues: []
  }).summary, "native .NET launcher");
});
