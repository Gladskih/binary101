"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { upxAdler32 } from "../../../../../analyzers/pe/packers/upx-adler32.js";

void test("upxAdler32 uses the Adler-32 initial value for empty input", () => {
  assert.equal(upxAdler32(new Uint8Array()), 1);
});

void test("upxAdler32 matches the RFC 1950 example", () => {
  // RFC 1950 section 9 gives Adler-32("Wikipedia") = 0x11e60398.
  // https://www.rfc-editor.org/rfc/rfc1950#section-9
  assert.equal(upxAdler32(new TextEncoder().encode("Wikipedia")), 0x11e60398);
});
