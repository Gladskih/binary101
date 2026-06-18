"use strict";

import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { test } from "node:test";
import {
  computeDigest,
  resolveDigestAlgorithmByName,
  resolveDigestAlgorithmByOid
} from "../../../../../analyzers/pe/authenticode/digest-algorithms.js";

const toHex = (buffer: ArrayBuffer): string =>
  Buffer.from(buffer).toString("hex");

void test("computeDigest supports RFC 1321 MD5 test vectors", async () => {
  const digest = await computeDigest("MD5", new TextEncoder().encode("abc").buffer);

  assert.strictEqual(digest.byteLength, 16);
  assert.strictEqual(toHex(digest), "900150983cd24fb0d6963f7d28e17f72");
});

void test("computeDigest supports SHA-224 without relying on Web Crypto", async () => {
  const data = new TextEncoder().encode("binary101");
  const digest = await computeDigest("SHA-224", data.buffer);

  assert.strictEqual(toHex(digest), createHash("sha224").update(data).digest("hex"));
});

void test("digest algorithm resolution accepts Authenticode names and OIDs", () => {
  assert.strictEqual(resolveDigestAlgorithmByName("Sha_512-224"), "SHA-512/224");
  assert.strictEqual(resolveDigestAlgorithmByOid("1.2.840.113549.2.5"), "MD5");
  assert.strictEqual(resolveDigestAlgorithmByOid("1.2.3.4"), undefined);
});
