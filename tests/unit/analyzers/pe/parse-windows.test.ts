"use strict";

import assert from "node:assert/strict";
import test from "node:test";
import { IMAGE_FILE_MACHINE_AMD64, IMAGE_FILE_MACHINE_I386 } from "../../../../analyzers/coff/machine.js";
import { PE32_PLUS_OPTIONAL_HEADER_MAGIC } from "../../../../analyzers/pe/optional-header/magic.js";
import { selectPeVariantParsers } from "../../../../analyzers/pe/parse-variant.js";
import { parseWindowsPe } from "../../../../analyzers/pe/parse-windows.js";
import { parseBrowserManifestXmlDocument } from "../../../../analyzers/pe/resources/preview/manifest-xml.js";
import { nativeAotHintContext, managedAotHintContext } from "../../../helpers/pe-relocation-discovery.js";

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

void test("preserves NativeAOT section hints when there is no CLR directory", async () => {
  const context = await nativeAotHintContext();
  const parsed = await parseWindowsPe(context.file, context.file, context.core, parseBrowserManifestXmlDocument);
  assert.equal(parsed.nativeAotCandidate?.status, "candidate");
});

void test("does not infer NativeAOT from section hints when CLR is present", async () => {
  const context = await managedAotHintContext();
  const parsed = await parseWindowsPe(context.file, context.file, context.core, parseBrowserManifestXmlDocument);
  assert.ok(parsed.clr);
  assert.equal(parsed.nativeAotCandidate, null);
});
