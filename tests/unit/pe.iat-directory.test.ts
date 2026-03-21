"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { parseIatDirectory } from "../../analyzers/pe/iat-directory.js";

void test("parseIatDirectory returns null when the IAT data directory is absent", () => {
  assert.equal(parseIatDirectory([], value => value, () => {}), null);
});

void test("parseIatDirectory preserves declared but malformed IAT directories with warnings", () => {
  const zeroRva = parseIatDirectory(
    [{ name: "IAT", rva: 0, size: 0x20 }],
    value => value,
    () => {}
  );
  assert.ok(zeroRva);
  assert.ok(zeroRva.warnings?.some(warning => /RVA is 0/i.test(warning)));

  const unmapped = parseIatDirectory(
    [{ name: "IAT", rva: 0x1000, size: 0x20 }],
    () => null,
    () => {}
  );
  assert.ok(unmapped);
  assert.ok(unmapped.warnings?.some(warning => /could not be mapped/i.test(warning)));
});
