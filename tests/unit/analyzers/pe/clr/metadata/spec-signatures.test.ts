"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import {
  parseMethodSpecSignature, parsePropertySignature, parseStandaloneSignature, parseTypeSpecSignature
} from "../../../../../../analyzers/pe/clr/metadata-spec-signatures.js";

void test("decodes standalone call sites and property indexers", () => {
  assert.deepEqual(parseStandaloneSignature(Uint8Array.of(0, 1, 1, 8), "Call site"), {
    callingConvention: 0, parameterCount: 1, returnType: "void", parameterTypes: ["i4"]
  });
  assert.deepEqual(parsePropertySignature(Uint8Array.of(8, 1, 0x0e, 8), "Indexer"), {
    callingConvention: 8, parameterCount: 1, returnType: "string", parameterTypes: ["i4"]
  });
});

for (const bytes of [[], [0], [0x0a], [0x0a, 0], [0x0a, 2, 8], [0x0a, 1, 0xff], [0x0a, 1, 8, 8]]) {
  void test(`rejects malformed MethodSpec ${bytes.join(",")}`, () => {
    assert.ok(parseMethodSpecSignature(Uint8Array.from(bytes), "MethodSpec").issues?.length);
  });
}

void test("reports malformed locals, property headers and type specifications", () => {
  assert.ok(parseStandaloneSignature(Uint8Array.of(), "Empty").issues?.length);
  assert.ok(parseStandaloneSignature(Uint8Array.of(7, 0), "Empty locals").issues?.length);
  assert.ok(parsePropertySignature(Uint8Array.of(0, 0, 1), "Wrong kind").issues?.length);
  assert.ok(parseTypeSpecSignature(Uint8Array.of(8, 8), "Trailing").issues?.length);
  assert.ok(parseTypeSpecSignature(Uint8Array.of(), "Empty").issues?.length);
});

void test("reports the signature kind when MethodSpec contains a valid local signature", () => {
  const decoded = parseMethodSpecSignature(Uint8Array.of(7, 1, 8), "MethodSpec");
  assert.deepEqual(decoded.types, []);
  assert.match(decoded.issues?.[0] ?? "", /signature header 0xa/);
});

void test("returns no invented types when counts are absent or zero", () => {
  assert.deepEqual(parseMethodSpecSignature(Uint8Array.of(0x0a), "Missing").types, []);
  assert.deepEqual(parseMethodSpecSignature(Uint8Array.of(0x0a, 0), "Zero").types, []);
  assert.match(parseMethodSpecSignature(Uint8Array.of(0x0a, 0), "Zero").issues?.[0] ?? "", /no elements/);
  assert.deepEqual(parseStandaloneSignature(Uint8Array.of(0xff), "Bad header"), {
    types: [], issues: ["Bad header signature has an invalid method/property calling convention."]
  });
});

void test("checks trailing bytes in local signatures and reports property-kind failures", () => {
  assert.match(parseStandaloneSignature(Uint8Array.of(7, 1, 8, 8), "Locals").issues?.[0] ?? "", /trailing/);
  assert.deepEqual(parsePropertySignature(Uint8Array.of(0, 0, 1), "Property"), {
    types: [], issues: ["Property signature has an invalid PROPERTY header."]
  });
});
