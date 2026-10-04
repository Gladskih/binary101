"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { ClrAssemblyCatalog } from "../../../../../../analyzers/pe/clr/metadata-assembly-catalog.js";
import { clrAssemblyReference, clrResolutionFixture } from "../../../../../helpers/clr-resolution-fixture.js";

void test("selects references by exact metadata identity and ignores repeated objects", () => {
  const library = clrResolutionFixture("Library");
  const issues: string[] = [];
  const catalog = new ClrAssemblyCatalog([library, library], issues);
  assert.strictEqual(catalog.resolveReference(clrAssemblyReference()), library);
  assert.strictEqual(catalog.resolveName({ name: "library", version: "1.2" }), library);
  assert.deepEqual(issues, []);
});

for (const reference of [undefined, { ...clrAssemblyReference(), version: "1.2.3.5" },
  { ...clrAssemblyReference(), culture: "ru" }, { ...clrAssemblyReference(), flags: 0x200 },
  { ...clrAssemblyReference(), publicKeyOrToken: Array(8).fill(1) },
  { ...clrAssemblyReference(), publicKeyOrToken: null }]) {
  void test(`rejects unavailable or mismatched assembly reference ${JSON.stringify(reference)}`, () => {
    const issues: string[] = [];
    assert.equal(new ClrAssemblyCatalog([clrResolutionFixture("Library")], issues).resolveReference(reference), null);
    assert.match(issues.join(";"), /unavailable or mismatched/);
  });
}

void test("rejects identity collisions and ambiguous partial names", () => {
  const issues: string[] = [];
  const catalog = new ClrAssemblyCatalog([clrResolutionFixture("Library"), clrResolutionFixture("Library")], issues);
  assert.equal(catalog.resolveReference(clrAssemblyReference()), null);
  assert.equal(catalog.resolveName({ name: "library" }), null);
  assert.deepEqual(issues, ["Assembly dependency Library 1.2.3.4 is ambiguous.", "Assembly dependency library is ambiguous."]);
});

void test("reports missing names and malformed selected assembly identities", () => {
  const issues: string[] = [];
  const malformed = clrResolutionFixture();
  malformed.assembly = null;
  const catalog = new ClrAssemblyCatalog([malformed], issues);
  assert.equal(catalog.resolveName({}), null);
  assert.equal(catalog.resolveName({ name: "missing" }), null);
  assert.equal(issues.length, 3);
  assert.equal(issues[0], "Dependency assembly identity is absent or malformed.");
  assert.equal(issues[2], "Assembly dependency missing is unavailable or mismatched.");
});

void test("matches every supplied display-name identity component including complete versions", () => {
  const library = clrResolutionFixture("Library");
  const catalog = new ClrAssemblyCatalog([library], []);
  assert.strictEqual(catalog.resolveName({ name: "library", version: "1.2.3.4", culture: "" }), library);
  assert.equal(catalog.resolveName({ name: "library", version: "1.2.3.5" }), null);
  assert.equal(catalog.resolveName({ name: "library", version: "1.20" }), null);
  assert.equal(catalog.resolveName({ name: "library", culture: "ru" }), null);
  assert.equal(catalog.resolveName({ name: "library", publicKeyToken: "ffffffffffffffff" }), null);
  assert.equal(catalog.resolveName({ name: "library", contentType: 0x200 }), null);
  assert.equal(catalog.resolveName({ name: "library", processorArchitecture: 1 }), null);
});
