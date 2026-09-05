import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { test } from "node:test";
import { APP_BINARY_PLACEHOLDER, APP_BINARY_PLACEHOLDER_TEXT, BINDING_PATTERNS, BUNDLE_SIGNATURE }
  from "../../../../../analyzers/pe/apphost/patterns.js";

void test("apphost marker matches upstream's SHA-256 definition", () => {
  // The literal 32-byte marker in bundle_marker.c includes LF in its SHA-256 input,
  // although the upstream explanatory comment does not mention the line ending.
  assert.deepEqual(BUNDLE_SIGNATURE,
    new Uint8Array(createHash("sha256").update(".net core bundle\n").digest()));
});

void test("apphost placeholder matches upstream's encoded SHA-256 definition", () => {
  // apphost.c EMBED_HASH_FULL_UTF8 is SHA-256("foobar") encoded as hexadecimal.
  assert.equal(APP_BINARY_PLACEHOLDER_TEXT, createHash("sha256").update("foobar").digest("hex"));
  assert.deepEqual(APP_BINARY_PLACEHOLDER,
    new TextEncoder().encode(createHash("sha256").update("foobar").digest("hex")));
});

void test("apphost patterns include every ASCII DLL case and the unbound placeholder", () => {
  assert.deepEqual(BINDING_PATTERNS.map(bytes => new TextDecoder().decode(bytes)).sort(), [
    ".dll\0", ".dlL\0", ".dLl\0", ".dLL\0", ".Dll\0", ".DlL\0", ".DLl\0", ".DLL\0",
    createHash("sha256").update("foobar").digest("hex")
  ].sort());
});
