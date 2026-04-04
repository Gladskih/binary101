"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import {
  renderImportLinking,
  renderImports,
  renderBoundImports,
  renderDelayImports,
  renderIat
} from "../../renderers/pe/import-sections.js";
import {
  createPeWithImportLinking,
  createPeWithInferredEagerIatOnly
} from "../fixtures/pe-import-linking-fixture.js";

void test("renderImportLinking and related sections surface confirmed and non-canonical import relationships", () => {
  const pe = createPeWithImportLinking();
  const out: string[] = [];

  renderImportLinking(pe, out);
  renderImports(pe, out);
  renderBoundImports(pe, out);
  renderDelayImports(pe, out);
  renderIat(pe, out);

  const html = out.join("");
  assert.ok(html.includes("Import linkage"));
  assert.ok(html.includes("Validated checks"));
  assert.ok(html.includes("Warnings"));
  assert.ok(html.includes("IAT fallback / FirstThunk"));
  assert.ok(html.includes("Matched BOUND_IMPORT entry"));
  assert.ok(html.includes("Delay-load IAT is isolated in the canonical .didat section"));
  assert.ok(html.includes("Names come from OriginalFirstThunk / the Import Lookup Table (INT)."));
  assert.ok(
    html.includes(
      "Import descriptor TimeDateStamp is non-zero, but no matching BOUND_IMPORT entry was found."
    )
  );
  assert.ok(html.includes("Load Config delay-IAT flags"));
  assert.ok(html.includes("Protected delay-load modules"));
  assert.ok(html.includes("Bound import entry without a matching eager import descriptor."));
  assert.ok(html.includes("Declared vs inferred eager IAT"));
  assert.ok(html.includes("Declared IAT covers all inferred eager IAT ranges"));
  assert.ok(html.includes("Show inferred eager IAT ranges"));
});

void test("renderIat shows inferred eager IAT ranges even when IMAGE_DIRECTORY_ENTRY_IAT is absent", () => {
  const pe = createPeWithInferredEagerIatOnly();
  const out: string[] = [];

  renderIat(pe, out);

  const html = out.join("");
  assert.ok(html.includes("Import Address Tables (IAT)"));
  assert.ok(html.includes("Declared IAT directory"));
  assert.ok(html.includes("Absent"));
  assert.ok(html.includes("Inferred eager IAT ranges"));
  assert.ok(
    html.includes(
      "IMAGE_DIRECTORY_ENTRY_IAT is absent, but eager IAT ranges were inferred from FirstThunk values in the import descriptors."
    )
  );
});
