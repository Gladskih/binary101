import assert from "node:assert/strict";
import { test } from "node:test";
import { computePeAuthenticodeDigest, verifyAuthenticode } from "../../../../../analyzers/pe/authenticode/verify.js";
import { decodePkcs7 } from "../../../../../analyzers/pe/authenticode/index.js";
import { renderAuthenticodeTree } from "../../../../../renderers/pe/security-tree.js";
import { createStrictAuthenticodeFixture } from "../../../../fixtures/pe-authenticode-fixtures.js";
import type { AuthenticodeVerificationInfo } from "../../../../../analyzers/pe/authenticode/index.js";
import {
  createNestedAuthenticodeCmsPayload,
  createNestedAuthenticodeLimitPayload
} from "../../../../fixtures/pe-authenticode-nested-cms-fixture.js";

void test("verifyAuthenticode checks a nested CMS payload independently of its parent", async () => {
  const { core, file, securityDir } = createStrictAuthenticodeFixture();
  const digest = await computePeAuthenticodeDigest(file, core, securityDir, "SHA-256");
  assert.ok(digest);
  const payload = await createNestedAuthenticodeCmsPayload("00".repeat(32), digest);
  const auth = decodePkcs7(payload);
  let digestLookups = 0;

  auth.verification = await verifyAuthenticode(file, core, securityDir, auth, payload, async () => {
    digestLookups += 1;
    return Uint8Array.from(Buffer.from(digest, "hex")).buffer;
  });
  const nested = auth.verification.nestedSignatures?.[0];
  const html = renderAuthenticodeTree({
    offset: 0, length: payload.length + 8, availableBytes: payload.length + 8,
    revision: 0x200, revisionName: "2.0", certificateType: 2, typeName: "PKCS#7", authenticode: auth
  });

  assert.equal(digestLookups, 1);
  assert.equal(auth.verification.fileDigestMatches, false);
  assert.equal(auth.verification.nestedSignatures?.length, 1);
  assert.equal(nested?.signerIndex, 0);
  assert.equal(nested?.signature.verification?.fileDigestMatches, true);
  assert.equal(nested?.signature.verification?.signerVerifications?.[0]?.signatureVerified, true);
  assert.match(auth.verification.warnings?.join(" ") ?? "", /Signer 1: nested signature.*ContentInfo/);
  assert.match(html, /Nested signature 1/);
});

const nestedResults = (verification: AuthenticodeVerificationInfo | undefined):
  AuthenticodeVerificationInfo[] =>
  verification?.nestedSignatures?.flatMap(({ signature }) => signature.verification
    ? [signature.verification, ...nestedResults(signature.verification)] : []) ?? [];

void test("verifyAuthenticode bounds nested signature depth and total work", async () => {
  const { core, file, securityDir } = createStrictAuthenticodeFixture();
  const digest = await computePeAuthenticodeDigest(file, core, securityDir, "SHA-256");
  assert.ok(digest);
  const payload = await createNestedAuthenticodeLimitPayload(digest);

  const verified = await verifyAuthenticode(file, core, securityDir, decodePkcs7(payload), payload);
  const branches = nestedResults(verified);

  // The root's first three grandchildren are reached before the breadth budget stops siblings.
  assert.equal(verified.nestedSignatures?.length, 13);
  assert.equal(branches.length, 16);
  assert.match(verified.warnings?.join(" ") ?? "", /per-signature analysis limit/);
  assert.match(verified.warnings?.join(" ") ?? "", /nested signatures exceed the analysis limit/);
  assert.match(branches[3]?.warnings?.join(" ") ?? "", /nested signatures exceed the analysis limit/);
});
