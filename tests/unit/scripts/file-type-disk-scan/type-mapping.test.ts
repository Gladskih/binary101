"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import {
  compareTypes,
  normalizeAnalyzerLabel,
  normalizeFileMimeType,
  typesMatch
} from "../../../../scripts/file-type-disk-scan/type-mapping.js";

void test("typesMatch treats PE analyzer labels and file.exe MIME as the same type", () => {
  assert.equal(typesMatch("PE32+ executable for x86-64 (AMD64)", "application/x-dosexec"), true);
});

void test("typesMatch maps legacy NE executable MIME to PE-family labels", () => {
  assert.equal(typesMatch("NE executable (16-bit Windows/OS/2)", "application/x-ms-ne-executable"), true);
  assert.equal(normalizeFileMimeType("application/x-ms-ne-executable suffix"), "unmapped");
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

void test("typesMatch maps Chrome extension packages to ZIP-family MIME", () => {
  assert.equal(typesMatch("Chrome extension package (CRX signed ZIP)", "application/x-chrome-extension"), true);
  assert.equal(typesMatch("ZIP archive", "application/x-chrome-extension"), true);
  assert.equal(normalizeAnalyzerLabel("prefix Chrome extension package"), "unmapped");
  assert.equal(normalizeFileMimeType("application/x-chrome-extension suffix"), "unmapped");
});

void test("typesMatch maps NuGet package MIME to ZIP-family labels", () => {
  assert.equal(typesMatch("ZIP archive", "application/vnd.nuget.package"), true);
  assert.equal(
    typesMatch("OpenXML Office document (DOCX/XLSX/PPTX)", "application/vnd.nuget.package"),
    true
  );
  assert.equal(normalizeFileMimeType("application/vnd.nuget.package suffix"), "unmapped");
});

void test("typesMatch maps COFF object labels to file.exe COFF MIME", () => {
  assert.equal(typesMatch("COFF object file for x86 (I386)", "application/x-coff"), true);
  assert.equal(normalizeAnalyzerLabel("prefix COFF object file for x86 (I386)"), "unmapped");
  assert.equal(normalizeFileMimeType("application/x-coff suffix"), "unmapped");
});

void test("typesMatch maps MSI MIME to Compound File labels", () => {
  assert.equal(
    typesMatch("Microsoft Compound File (e.g. Office 97-2003, MSI)", "application/x-msi"),
    true
  );
  assert.equal(typesMatch("Windows Installer package (MSI)", "application/x-msi"), true);
  assert.equal(normalizeFileMimeType("application/x-msi suffix"), "unmapped");
});

void test("typesMatch maps legacy Word MIME to Compound File labels", () => {
  assert.equal(
    typesMatch("Microsoft Compound File (e.g. Office 97-2003, MSI)", "application/msword"),
    true
  );
  assert.equal(typesMatch("Microsoft Word binary document (DOC)", "application/msword"), true);
  assert.equal(normalizeFileMimeType("application/msword suffix"), "unmapped");
});

void test("typesMatch keeps genuine media mismatches visible", () => {
  assert.equal(typesMatch("PNG image", "image/jpeg"), false);
});

void test("typesMatch maps AVIF image labels to file.exe AVIF MIME", () => {
  const label = "AVIF image (AV1 Image File Format, ISO-BMFF)";
  assert.equal(typesMatch(label, "image/avif"), true);
  assert.equal(normalizeAnalyzerLabel("prefix AVIF image"), "unmapped");
  assert.equal(normalizeFileMimeType("image/avif suffix"), "unmapped");
});

void test("typesMatch maps Windows bitmap cursor MIME to ICO/CUR icon labels", () => {
  assert.equal(typesMatch("ICO/CUR icon image", "image/x-win-bitmap"), true);
  assert.equal(normalizeFileMimeType("image/x-win-bitmap suffix"), "unmapped");
});

void test("typesMatch maps ANI MIME to animated cursor labels", () => {
  assert.equal(typesMatch("Windows animated cursor (ANI)", "application/x-navi-animation"), true);
  assert.equal(normalizeFileMimeType("application/x-navi-animation suffix"), "unmapped");
});

void test("typesMatch treats JavaScript MIME as text-like shallow analyzer output", () => {
  assert.equal(typesMatch("Text file", "application/javascript"), true);
});

void test("typesMatch maps newline-delimited JSON MIME to JSON analyzer output", () => {
  assert.equal(typesMatch("JSON data", "application/x-ndjson"), true);
});

void test("typesMatch maps XHTML MIME to XML analyzer output", () => {
  assert.equal(typesMatch("XML document", "application/xhtml+xml"), true);
  assert.equal(normalizeFileMimeType("application/xhtml+xml suffix"), "unmapped");
});

void test("typesMatch maps empty files", () => {
  assert.equal(typesMatch("Empty file", "inode/x-empty"), true);
});

void test("typesMatch maps ar archives to file.exe archive MIME", () => {
  assert.equal(typesMatch("Unix ar archive (static library)", "application/x-archive"), true);
  assert.equal(typesMatch("Unix ar archive (thin static library)", "application/x-archive"), true);
  assert.equal(normalizeAnalyzerLabel("prefix Unix ar archive (static library)"), "unmapped");
  assert.equal(normalizeAnalyzerLabel("Unix ar archive (static library) suffix"), "unmapped");
  assert.equal(normalizeFileMimeType("prefix application/x-archive"), "unmapped");
  assert.equal(normalizeFileMimeType("application/x-archive suffix"), "unmapped");
});

void test("typesMatch maps WIM deployment images to file.exe WIM MIME", () => {
  const label = "Windows Imaging Format archive (WIM/PPKG deployment image)";
  assert.equal(typesMatch(label, "application/x-ms-wim"), true);
  assert.equal(normalizeAnalyzerLabel("prefix Windows Imaging Format archive"), "unmapped");
  assert.equal(normalizeFileMimeType("application/x-ms-wim suffix"), "unmapped");
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

void test("comparison credits MSDelta when file.exe only reports generic binary data", () => {
  assert.equal(
    compareTypes("MSDelta patch payload (PA30)", "application/octet-stream"),
    "analyzer-more-specific"
  );
  assert.equal(typesMatch("MSDelta patch payload (PA30)", "application/octet-stream"), true);
});

void test("comparison credits structured text detected more precisely than file.exe", () => {
  assert.equal(compareTypes("XML document", "text/plain"), "analyzer-more-specific");
  assert.equal(compareTypes("JSON data", "text/plain"), "analyzer-more-specific");
  assert.equal(
    compareTypes("SVG image (XML vector graphics)", "text/plain"),
    "analyzer-more-specific"
  );
});

void test("comparison does not hide unknown analyzer labels or specific MIME types", () => {
  assert.equal(compareTypes("Unknown binary type", "application/octet-stream"), "match");
  assert.equal(compareTypes("Unexpected custom label", "application/octet-stream"), "mismatch");
  assert.equal(compareTypes("Text file", "application/etl"), "mismatch");
});

void test("file MIME mapping checks CAB before the generic Microsoft vendor family", () => {
  assert.equal(normalizeFileMimeType("application/vnd.ms-cab-compressed"), "cab");
  assert.equal(typesMatch("Microsoft Cabinet archive", "application/vnd.ms-cab-compressed"), true);
});

void test("file MIME mapping handles specific Microsoft font types before the vendor family", () => {
  const label = "TrueType/OpenType font (sfnt glyph outlines)";
  assert.equal(normalizeFileMimeType("application/vnd.ms-opentype"), "font-ttf");
  assert.equal(normalizeFileMimeType("application/vnd.ms-fontobject"), "font-eot");
  assert.equal(typesMatch(label, "application/vnd.ms-opentype"), true);
});

void test("typesMatch maps M4A MIME to the MP4 container family", () => {
  assert.equal(typesMatch("MP4/QuickTime container (ISO-BMFF)", "audio/x-m4a"), true);
});

void test("typesMatch maps Windows Help MIME aliases to HLP labels", () => {
  assert.equal(typesMatch("Windows Help file (HLP)", "application/x-winhelp"), true);
  assert.equal(typesMatch("Windows Help file (HLP)", "application/winhlp"), true);
  assert.equal(normalizeFileMimeType("application/x-winhelp suffix"), "unmapped");
});

void test("typesMatch maps compiled terminfo entries to file.exe terminfo MIME types", () => {
  const label = 'Compiled terminfo entry "vt100" (terminal capability database)';
  assert.equal(typesMatch(label, "application/x-terminfo"), true);
  assert.equal(typesMatch(label, "application/x-terminfo2"), true);
  assert.equal(normalizeAnalyzerLabel("prefix Compiled terminfo entry"), "unmapped");
  assert.equal(normalizeFileMimeType("application/x-terminfo3"), "unmapped");
});

void test("typesMatch maps Windows INF setup scripts to file.exe setupscript MIME", () => {
  const label = "Windows setup information file (INF, driver/install directives)";
  assert.equal(typesMatch(label, "application/x-setupscript"), true);
  assert.equal(normalizeAnalyzerLabel("prefix Windows setup information file"), "unmapped");
  assert.equal(normalizeFileMimeType("application/x-setupscript suffix"), "unmapped");
});

void test("typesMatch maps gettext message catalogs to file.exe gettext MIME", () => {
  const label = "GNU gettext message catalog (MO translations)";
  assert.equal(typesMatch(label, "application/x-gettext-translation"), true);
  assert.equal(normalizeAnalyzerLabel("prefix GNU gettext message catalog"), "unmapped");
  assert.equal(normalizeFileMimeType("application/x-gettext-translation suffix"), "unmapped");
});

void test("typesMatch maps SDB labels to file.exe SDB MIME", () => {
  const label = "Windows Application Compatibility Database (SDB shim database)";
  assert.equal(typesMatch(label, "application/x-ms-sdb"), true);
  assert.equal(normalizeAnalyzerLabel("prefix Windows Application Compatibility Database"), "unmapped");
  assert.equal(normalizeFileMimeType("application/x-ms-sdb suffix"), "unmapped");
});

void test("typesMatch maps TrueType font labels to file.exe font MIME", () => {
  const label = "TrueType/OpenType font (sfnt glyph outlines)";
  assert.equal(typesMatch(label, "font/ttf"), true);
  assert.equal(normalizeAnalyzerLabel("prefix TrueType/OpenType font"), "unmapped");
  assert.equal(normalizeFileMimeType("font/ttf suffix"), "unmapped");
});

void test("typesMatch maps OpenType font collections to file.exe font MIME", () => {
  const label = "OpenType font collection (TTC/OTC shared font tables)";
  assert.equal(typesMatch(label, "font/ttf"), true);
  assert.equal(normalizeAnalyzerLabel(`prefix ${label}`), "unmapped");
});

void test("typesMatch maps WOFF2 font labels to file.exe WOFF2 MIME", () => {
  const label = "Web Open Font Format 2 font (WOFF2 compressed web font)";
  assert.equal(typesMatch(label, "font/woff2"), true);
  assert.equal(normalizeAnalyzerLabel("prefix Web Open Font Format 2 font"), "unmapped");
  assert.equal(normalizeFileMimeType("font/woff2 suffix"), "unmapped");
});

void test("typesMatch maps WOFF font labels to file.exe WOFF MIME", () => {
  const label = "Web Open Font Format font (WOFF compressed web font)";
  assert.equal(typesMatch(label, "font/woff"), true);
  assert.equal(normalizeAnalyzerLabel("prefix Web Open Font Format font"), "unmapped");
  assert.equal(normalizeFileMimeType("font/woff suffix"), "unmapped");
});

void test("typesMatch maps Python bytecode labels to file.exe bytecode MIME", () => {
  const label = "Python bytecode cache (PYC compiled module)";
  assert.equal(typesMatch(label, "application/x-bytecode.python"), true);
  assert.equal(normalizeAnalyzerLabel("prefix Python bytecode cache"), "unmapped");
  assert.equal(normalizeFileMimeType("application/x-bytecode.python suffix"), "unmapped");
});

void test("typesMatch maps PEM armor labels to file.exe PEM MIME", () => {
  const label = "PEM armor block (certificate/key text encoding)";
  assert.equal(typesMatch(label, "application/x-pem-file"), true);
  assert.equal(normalizeAnalyzerLabel("prefix PEM armor block"), "unmapped");
  assert.equal(normalizeFileMimeType("application/x-pem-file suffix"), "unmapped");
});

void test("typesMatch maps PostScript labels to file.exe PostScript MIME", () => {
  const label = "PostScript document (page description program)";
  assert.equal(typesMatch(label, "application/postscript"), true);
  assert.equal(normalizeAnalyzerLabel("prefix PostScript document"), "unmapped");
  assert.equal(normalizeFileMimeType("application/postscript suffix"), "unmapped");
});

void test("typesMatch maps PPD labels to file.exe PPD MIME", () => {
  const label = "PostScript Printer Description file (PPD printer driver metadata)";
  assert.equal(typesMatch(label, "application/vnd.cups-ppd"), true);
  assert.equal(normalizeAnalyzerLabel("prefix PostScript Printer Description file"), "unmapped");
  assert.equal(normalizeFileMimeType("application/vnd.cups-ppd suffix"), "unmapped");
});

void test("typesMatch treats uncommon text subtypes as text-like", () => {
  assert.equal(typesMatch("Text script (shebang)", "text/x-perl"), true);
  assert.equal(typesMatch("Text file", "application/x-wine-extension-ini"), true);
});

void test("normalizers expose unmapped values for report diagnostics", () => {
  assert.equal(normalizeAnalyzerLabel("Unexpected custom label"), "unmapped");
  assert.equal(normalizeFileMimeType("application/x-custom-format"), "unmapped");
});
