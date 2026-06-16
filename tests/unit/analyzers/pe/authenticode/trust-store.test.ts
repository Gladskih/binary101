"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import {
  hasAuthenticodeTrustStoreData,
  normalizeAuthenticodeTrustStore,
  normalizeThumbprint
} from "../../../../../analyzers/pe/authenticode/trust-store.js";

void test("normalizeThumbprint strips separators and uppercases SHA-1 values", () => {
  assert.strictEqual(normalizeThumbprint("aa bb-cc"), "AABBCC");
  assert.strictEqual(normalizeThumbprint(""), undefined);
});

void test("normalizeAuthenticodeTrustStore keeps trusted and revoked CA entries", () => {
  const snapshot = normalizeAuthenticodeTrustStore({
    schemaVersion: 1,
    generatedAt: "2026-05-03T00:00:00.000Z",
    source: "unit",
    trustedCAs: [
      {
        thumbprint: "aa bb",
        subject: "CN=Trusted Root",
        issuer: "CN=Trusted Root",
        serialNumber: "01",
        derBase64: "AQID",
        stores: ["Root", "Root", "AuthRoot"]
      }
    ],
    revokedCAs: [{ thumbprint: "cc dd", stores: ["Disallowed"] }]
  });

  assert.strictEqual(snapshot.generatedAt, "2026-05-03T00:00:00.000Z");
  assert.strictEqual(snapshot.trustedCAs[0]?.thumbprint, "AABB");
  assert.strictEqual(snapshot.trustedCAs[0]?.derBase64, "AQID");
  assert.deepStrictEqual(snapshot.trustedCAs[0]?.stores, ["AuthRoot", "Root"]);
  assert.strictEqual(snapshot.revokedCAs[0]?.thumbprint, "CCDD");
  assert.strictEqual(hasAuthenticodeTrustStoreData(snapshot), true);
});

void test("normalizeAuthenticodeTrustStore reports malformed snapshots without throwing", () => {
  const snapshot = normalizeAuthenticodeTrustStore({
    schemaVersion: 2,
    generatedAt: "2026-05-03T00:00:00.000Z",
    trustedCAs: [{ subject: "missing thumbprint" }],
    revokedCAs: "bad"
  });

  assert.deepStrictEqual(snapshot.trustedCAs, []);
  assert.deepStrictEqual(snapshot.revokedCAs, []);
  assert.strictEqual(hasAuthenticodeTrustStoreData(snapshot), false);
  assert.ok(snapshot.warnings?.some(warning => warning.includes("schemaVersion")));
  assert.ok(snapshot.warnings?.some(warning => warning.includes("thumbprint")));
  assert.ok(snapshot.warnings?.some(warning => warning.includes("revokedCAs")));
});
