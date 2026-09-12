"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { formatPublicKeyToken, parseStrongName } from "../../../../../analyzers/pe/clr/strong-name.js";
import { MockFile } from "../../../../helpers/mock-file.js";
import { makeClr, expectedPublicKeyToken, makeStrongNamePeFixture, makeValidSignedFixture, makeInvalidSignedFixture } from "../../../../helpers/pe-strong-name-fixture.js";

void test("formatPublicKeyToken uses the ECMA strong-name token byte order", async () => {
  const publicKey = Uint8Array.from({ length: Uint32Array.BYTES_PER_ELEMENT }, (_, index) => index + 1);
  const token = await formatPublicKeyToken(Array.from(publicKey));

  assert.strictEqual(token, await expectedPublicKeyToken(publicKey));
});

void test("parseStrongName reports absent signatures", async () => {
  const pe = makeStrongNamePeFixture();
  const parsed = await parseStrongName(
    new MockFile(new Uint8Array(pe.layout.fileSize)),
    rva => rva,
    makeClr(0, 0)
  );

  assert.strictEqual(parsed.status, "absent");
  assert.strictEqual(parsed.verification, "unknown");
});

void test("parseStrongName detects delay-signed all-zero signatures", async () => {
  const pe = makeStrongNamePeFixture();
  const parsed = await parseStrongName(
    new MockFile(new Uint8Array(pe.layout.fileSize)),
    rva => rva,
    makeClr(pe.layout.signatureOffset, pe.layout.signatureSize)
  );

  assert.strictEqual(parsed.status, "delay-signed");
  assert.match(parsed.verificationNote, /delay-signed/);
});

void test("parseStrongName reports unmapped and truncated signatures", async () => {
  const pe = makeStrongNamePeFixture();
  const unmapped = await parseStrongName(
    new MockFile(new Uint8Array(pe.layout.fileSize)),
    () => null,
    makeClr(pe.layout.signatureOffset, pe.layout.signatureSize)
  );
  const truncated = await parseStrongName(
    new MockFile(new Uint8Array(pe.layout.signatureOffset + Uint8Array.BYTES_PER_ELEMENT)),
    rva => rva,
    makeClr(pe.layout.signatureOffset, pe.layout.signatureSize)
  );

  assert.strictEqual(unmapped.status, "unmapped");
  assert.strictEqual(truncated.status, "truncated");
  assert.ok(truncated.issues.some(issue => issue.includes("truncated")));
});

void test("parseStrongName verifies valid RSA strong-name signatures", async () => {
  const fixture = await makeValidSignedFixture();

  const parsed = await parseStrongName(new MockFile(fixture.bytes), rva => rva, fixture.clr);

  assert.strictEqual(parsed.status, "present");
  assert.strictEqual(parsed.verification, "valid");
  assert.match(parsed.verificationNote, /matches/);
});

void test("parseStrongName reports invalid RSA strong-name signatures", async () => {
  const fixture = await makeInvalidSignedFixture();

  const parsed = await parseStrongName(new MockFile(fixture.bytes), rva => rva, fixture.clr);

  assert.strictEqual(parsed.status, "present");
  assert.strictEqual(parsed.verification, "invalid");
  assert.match(parsed.verificationNote, /does not match/);
});
