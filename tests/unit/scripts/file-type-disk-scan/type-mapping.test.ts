"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import {
  normalizeAnalyzerLabel,
  normalizeFileMimeType,
  typesMatch
} from "../../../../scripts/file-type-disk-scan/type-mapping.js";

void test("typesMatch treats PE analyzer labels and file.exe MIME as the same type", () => {
  assert.equal(typesMatch("PE32+ executable for x86-64 (AMD64)", "application/x-dosexec"), true);
});

void test("typesMatch maps ZIP-derived document refinements to ZIP MIME types", () => {
  assert.equal(
    typesMatch(
      "Microsoft Word document (DOCX)",
      "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
    ),
    true
  );
});

void test("typesMatch maps COFF object labels to file.exe COFF MIME", () => {
  assert.equal(typesMatch("COFF object file for x86 (I386)", "application/x-coff"), true);
  assert.equal(normalizeAnalyzerLabel("prefix COFF object file for x86 (I386)"), "unmapped");
  assert.equal(normalizeFileMimeType("application/x-coff suffix"), "unmapped");
});

void test("typesMatch keeps genuine media mismatches visible", () => {
  assert.equal(typesMatch("PNG image", "image/jpeg"), false);
});

void test("typesMatch treats JavaScript MIME as text-like shallow analyzer output", () => {
  assert.equal(typesMatch("Text file", "application/javascript"), true);
});

void test("typesMatch maps newline-delimited JSON MIME to JSON analyzer output", () => {
  assert.equal(typesMatch("JSON data", "application/x-ndjson"), true);
});

void test("typesMatch maps ar archives to file.exe archive MIME", () => {
  assert.equal(typesMatch("Unix ar archive (static library)", "application/x-archive"), true);
  assert.equal(typesMatch("Unix ar archive (thin static library)", "application/x-archive"), true);
  assert.equal(normalizeAnalyzerLabel("prefix Unix ar archive (static library)"), "unmapped");
  assert.equal(normalizeAnalyzerLabel("Unix ar archive (static library) suffix"), "unmapped");
  assert.equal(normalizeFileMimeType("prefix application/x-archive"), "unmapped");
  assert.equal(normalizeFileMimeType("application/x-archive suffix"), "unmapped");
});

void test("typesMatch maps SQLite WAL-index shared-memory files to SQLite MIME", () => {
  assert.equal(typesMatch("SQLite WAL-index shared-memory file", "application/vnd.sqlite3"), true);
  assert.equal(normalizeAnalyzerLabel("prefix SQLite WAL-index shared-memory file"), "unmapped");
  assert.equal(normalizeAnalyzerLabel("SQLite WAL-index shared-memory file suffix"), "unmapped");
});

void test("normalizer maps MSDelta patch payload labels", () => {
  assert.equal(normalizeAnalyzerLabel("MSDelta patch payload (PA30)"), "msdelta");
  assert.equal(normalizeAnalyzerLabel("MSDelta patch payload (PA31)"), "msdelta");
  assert.equal(normalizeAnalyzerLabel("prefix MSDelta patch payload (PA31)"), "unmapped");
  assert.equal(normalizeAnalyzerLabel("MSDelta patch payload (PA31) suffix"), "unmapped");
  assert.equal(normalizeAnalyzerLabel("MSDelta patch payload (PA32)"), "unmapped");
});

void test("typesMatch maps compiled terminfo entries to file.exe terminfo MIME types", () => {
  const label = 'Compiled terminfo entry "vt100" (terminal capability database)';
  assert.equal(typesMatch(label, "application/x-terminfo"), true);
  assert.equal(typesMatch(label, "application/x-terminfo2"), true);
  assert.equal(normalizeAnalyzerLabel("prefix Compiled terminfo entry"), "unmapped");
  assert.equal(normalizeFileMimeType("application/x-terminfo3"), "unmapped");
});

void test("typesMatch treats uncommon text subtypes as text-like", () => {
  assert.equal(typesMatch("Text script (shebang)", "text/x-perl"), true);
  assert.equal(typesMatch("Text file", "application/x-wine-extension-ini"), true);
});

void test("normalizers expose unmapped values for report diagnostics", () => {
  assert.equal(normalizeAnalyzerLabel("Unexpected custom label"), "unmapped");
  assert.equal(normalizeFileMimeType("application/x-custom-format"), "unmapped");
});
