"use strict";

import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { test } from "node:test";
import { getClrAssemblyIdentity, clrAssemblyIdentityKey }
  from "../../../../../../analyzers/pe/clr/metadata-assembly-identity.js";
import { clrAssemblyReference, clrResolutionFixture } from "../../../../../helpers/clr-resolution-fixture.js";

const assemblyWithoutKey = () => {
  const assembly = { ...clrResolutionFixture().assembly! };
  delete assembly.publicKey;
  return assembly;
};

void test("uses exact version, normalized name/culture, and full-key token", () => {
  const publicKey = Array.from(new TextEncoder().encode("public key fixture"));
  const assembly = { ...clrResolutionFixture().assembly!, publicKey, culture: "en-US" };
  const identity = getClrAssemblyIdentity(assembly)!;
  assert.equal(identity.publicKeyToken,
    createHash("sha1").update(new Uint8Array(publicKey)).digest().subarray(-8).reverse().toString("hex"));
  assert.equal(identity.name, "application");
  assert.equal(identity.culture, "en-us");
  assert.equal(identity.version, "1.2.3.4");
  assert.strictEqual(getClrAssemblyIdentity(assembly), identity);
  assert.equal(clrAssemblyIdentityKey(identity), JSON.stringify([
    "application", "1.2.3.4", "en-us", identity.publicKeyToken, 0, 0
  ]));
  assert.equal(getClrAssemblyIdentity({ ...clrAssemblyReference(), flags: 1,
    publicKeyOrToken: publicKey })!.publicKeyToken,
    identity.publicKeyToken);
});

void test("reads tokens as eight bytes rather than rehashing them", () => {
  assert.equal(getClrAssemblyIdentity({ ...clrAssemblyReference(),
    publicKeyOrToken: Array(8).fill(0xff) })!.publicKeyToken,
    "ffffffffffffffff");
  assert.equal(getClrAssemblyIdentity(clrAssemblyReference())!.publicKeyToken, "");
  assert.equal(getClrAssemblyIdentity({ ...clrResolutionFixture().assembly!, publicKey: [] })!.publicKeyToken, "");
  assert.equal(getClrAssemblyIdentity({ ...clrAssemblyReference(), flags: 0x200 })!.contentType, 0x200);
  assert.equal(getClrAssemblyIdentity({ ...clrAssemblyReference(),
    publicKeyOrToken: [0, 1, 2, 3, 4, 5, 6, 7] })!.publicKeyToken, "0001020304050607");
  assert.equal(getClrAssemblyIdentity({ ...clrAssemblyReference(), culture: "" })!.culture, "");
  assert.equal(getClrAssemblyIdentity({ ...clrAssemblyReference(), flags: 0x40 })!.processorArchitecture, 4);
});

for (const assembly of [null, { ...clrAssemblyReference(), name: null },
  { ...clrAssemblyReference(), culture: null },
  assemblyWithoutKey(),
  { ...clrResolutionFixture().assembly!, publicKey: [-1] },
  { ...clrAssemblyReference(), publicKeyOrToken: null }, { ...clrAssemblyReference(), publicKeyOrToken: [0] },
  { ...clrAssemblyReference(), publicKeyOrToken: [-1] }, { ...clrAssemblyReference(), publicKeyOrToken: [256] },
  { ...clrAssemblyReference(), publicKeyOrToken: [0.5] },
  { ...clrAssemblyReference(), publicKeyOrToken: [-1, 0, 0, 0, 0, 0, 0, 0] },
  { ...clrAssemblyReference(), publicKeyOrToken: [256, 0, 0, 0, 0, 0, 0, 0] },
  { ...clrAssemblyReference(), publicKeyOrToken: [0.5, 0, 0, 0, 0, 0, 0, 0] }]) {
  void test(`rejects absent or invalid assembly identities ${JSON.stringify(assembly)}`, () => {
    assert.equal(getClrAssemblyIdentity(assembly), null);
    assert.equal(getClrAssemblyIdentity(assembly), null);
  });
}
