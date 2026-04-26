"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { parseIatDirectory } from "../../analyzers/pe/imports/iat.js";

void test("parseIatDirectory returns null when the IAT data directory is absent", () => {
  assert.equal(parseIatDirectory([], value => value), null);
});

void test("parseIatDirectory preserves declared but malformed IAT directories with warnings", () => {
  const zeroRva = parseIatDirectory(
    [{ name: "IAT", rva: 0, size: 0x20 }],
    value => value
  );
  assert.ok(zeroRva);
  assert.ok(zeroRva.warnings?.some(warning => /RVA is 0/i.test(warning)));

  const zeroSize = parseIatDirectory(
    [{ name: "IAT", rva: 0x1000, size: 0 }],
    value => value
  );
  assert.ok(zeroSize);
  assert.ok(zeroSize.warnings?.some(warning => /size is 0/i.test(warning)));

  const unmapped = parseIatDirectory(
    [{ name: "IAT", rva: 0x1000, size: 0x20 }],
    () => null
  );
  assert.ok(unmapped);
  assert.ok(unmapped.warnings?.some(warning => /could not be mapped/i.test(warning)));
});

void test("parseIatDirectory rejects negative mapped offsets", () => {
  const result = parseIatDirectory(
    [{ name: "IAT", rva: 0x1000, size: 0x20 }],
    () => -4
  );

  assert.ok(result);
  assert.ok(result.warnings?.some(warning => /could not be mapped/i.test(warning)));
});
