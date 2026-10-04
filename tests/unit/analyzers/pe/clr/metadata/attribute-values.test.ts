"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { AttributeCursor } from "../../../../../../analyzers/pe/clr/metadata-attribute-cursor.js";
import { readFixedArgument } from "../../../../../../analyzers/pe/clr/metadata-attribute-values.js";

void test("decodes fixed argument values and distinguishes complete null from truncation", () => {
  assert.deepEqual(readFixedArgument(new AttributeCursor(Uint8Array.of(0xff), [], "String"), "string"),
    { argument: { type: "string", value: null }, complete: true });
  assert.deepEqual(readFixedArgument(new AttributeCursor(new Uint8Array(), [], "String"), "string"),
    { argument: { type: "string", value: null }, complete: false });
});

void test("rejects negative attribute array counts other than the null sentinel", () => {
  const issues: string[] = [];
  assert.equal(readFixedArgument(new AttributeCursor(Uint8Array.of(0xfe, 0xff, 0xff, 0xff), issues, "Array"),
    "string[]").complete, false);
  assert.match(issues[0] ?? "", /negative/);
});
