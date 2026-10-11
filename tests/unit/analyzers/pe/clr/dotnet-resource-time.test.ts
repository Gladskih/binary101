"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import {
  formatResourceDateTime, formatResourceTimeSpan
} from "../../../../../analyzers/pe/clr/dotnet-resource-time.js";

void test("DateTime preserves the entire .NET tick range", () => {
  assert.strictEqual(formatResourceDateTime(0n, 1), "0001-01-01T00:00:00.0000000 (Unspecified)");
  assert.strictEqual(formatResourceDateTime(3155378975999999999n, 2),
    "9999-12-31T23:59:59.9999999 (Unspecified)");
  assert.strictEqual(formatResourceDateTime(-1n, 1), null);
  assert.strictEqual(formatResourceDateTime(3155378976000000000n, 2), null);
});

void test("DateTime kind is interpreted only in v2", () => {
  assert.strictEqual(formatResourceDateTime(0x4000000000000000n, 2), "0001-01-01T00:00:00.0000000Z");
  assert.strictEqual(formatResourceDateTime(0x4000000000000000n, 1), null);
  assert.match(formatResourceDateTime(0x8000000000000000n, 2) ?? "", /Local DateTime.*time zone/);
});

void test("TimeSpan supports zero, whole seconds and signed Int64 extrema", () => {
  assert.strictEqual(formatResourceTimeSpan(0n), "00:00:00");
  assert.strictEqual(formatResourceTimeSpan(10000000n), "00:00:01");
  assert.strictEqual(formatResourceTimeSpan(9223372036854775807n), "10675199.02:48:05.4775807");
  assert.strictEqual(formatResourceTimeSpan(-9223372036854775808n), "-10675199.02:48:05.4775808");
});
