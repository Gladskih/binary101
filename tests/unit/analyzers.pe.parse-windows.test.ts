"use strict";

import assert from "node:assert/strict";
import test from "node:test";
import { IMAGE_FILE_MACHINE_AMD64, IMAGE_FILE_MACHINE_I386 } from "../../analyzers/pe/machine.js";
import { PE32_PLUS_OPTIONAL_HEADER_MAGIC } from "../../analyzers/pe/optional-header/magic.js";
import { selectPeVariantParsers } from "../../analyzers/pe/parse-variant.js";

void test("selectPeVariantParsers returns PE32+ parser family for PE32+ images", () => {
  const variant = selectPeVariantParsers(PE32_PLUS_OPTIONAL_HEADER_MAGIC, IMAGE_FILE_MACHINE_AMD64);
  assert.equal(typeof variant.parseAndEnrichLoadConfig, "function");
  assert.equal(typeof variant.parseImportDirectory, "function");
  assert.equal(typeof variant.parseTlsDirectory, "function");
  assert.equal(typeof variant.parseDelayImports, "function");
});

void test("selectPeVariantParsers returns PE32 parser family for i386 images", () => {
  const variant = selectPeVariantParsers(0x10b, IMAGE_FILE_MACHINE_I386);
  assert.equal(typeof variant.parseAndEnrichLoadConfig, "function");
  assert.equal(typeof variant.parseImportDirectory, "function");
  assert.equal(typeof variant.parseTlsDirectory, "function");
  assert.equal(typeof variant.parseDelayImports, "function");
});
