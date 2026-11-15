import assert from "node:assert/strict";
import { test } from "node:test";
import { renderChecksWithoutFindings } from "../../../renderers/checks-without-findings.js";
import { sanitizerPe, sanitizerElf } from "../../fixtures/sanitizer-metadata.js";
import { detectEmbeddedResources } from "../../../analyzers/embedded-resources/detect.js";
import { minimalRcc } from "../../fixtures/embedded-resource-builders.js";
import { MockFile } from "../../helpers/mock-file.js";
import { DOMParser } from "@xmldom/xmldom";
import { createPeDwarfFile } from "../../fixtures/pe-dwarf-file.js";
import { createPeRomFile } from "../../fixtures/sample-files-pe.js";
import { parsePe } from "../../../analyzers/pe/index.js";
import { parseElf } from "../../../analyzers/elf/index.js";
import { createElfNativeAotFixture } from "../../helpers/elf-native-aot-fixture.js";
import { createElfDwarfFile } from "../../fixtures/elf-dwarf-file.js";

void test("lists individual PE searches without grouping their negative results", () => {
  const pe = sanitizerPe();
  pe.packers = null;
  pe.embeddedResources = null;
  pe.sanitizerEvidence = [];
  const html = renderChecksWithoutFindings(pe);

  for (const name of ["Go runtime metadata", "D runtime metadata", "DWARF debug information",
    ".NET apphost", "Linux boot protocol", "NativeAOT", "MSVC C++ RTTI",
    "Itanium C++ RTTI", "Microsoft-compatible exception handling", "Qt RCC", "GLib GResource",
    "UPX executable packer", "Inno Setup installer", "NSIS installer", "Bun standalone executable",
    "ASan", "TSan", "UBSan"]) assert.ok(html.includes(`<li>${name}</li>`), name);
  assert.doesNotMatch(html, /PE packagers|Qt \/ GLib|<dt>Sanitizer evidence/);
  const document = new DOMParser({ onError: (_level, message) => assert.fail(message) })
    .parseFromString(html, "application/xml");
  assert.equal(document.documentElement?.getAttribute("data-analysis-origin"), "supplemental");
  assert.equal(document.getElementsByTagName("ul").length, 1);
  assert.ok(Array.from(document.getElementsByTagName("ul").item(0)!.childNodes)
    .every(node => node.nodeName === "li"));
  assert.ok(Array.from(document.getElementsByTagName("li")).every(item => item.textContent));
  assert.match(html, /not detected does not mean absent/);
  assert.ok(html.indexOf("<li>.NET apphost") < html.indexOf("<li>ASan"));
});

void test("keeps checks with no stored sanitizer or resource result out of those lists", () => {
  const html = renderChecksWithoutFindings(sanitizerPe());
  assert.doesNotMatch(html, /<li>ASan<\/li>|<li>Qt RCC<\/li>|<li>UPX executable packer<\/li>/);
  // Nineteen PE-specific entries plus DWARF; no optional check result was supplied.
  assert.equal(new DOMParser().parseFromString(html, "application/xml")
    .getElementsByTagName("li").length, 20);
});

void test("does not attach Windows-specific checks to ROM images", async () => {
  const pe = await parsePe(createPeRomFile());
  assert.ok(pe);

  const html = renderChecksWithoutFindings(pe);

  assert.doesNotMatch(html, /<li>Go runtime metadata<\/li>|<li>UPX executable packer<\/li>/);
  assert.match(html, /<li>DWARF debug information<\/li>/);
});

void test("does not report parsed DWARF as undetected", async () => {
  const pe = await parsePe(createPeDwarfFile());
  assert.ok(pe?.dwarf);

  assert.doesNotMatch(renderChecksWithoutFindings(pe), /<li>DWARF debug information<\/li>/);
});

void test("retains per-detector absences when another packager has findings or warnings", () => {
  const pe = sanitizerPe();
  pe.packers = { reports: [{ id: "upx", findings: [], warnings: ["Unreadable pack header"] }] };

  const html = renderChecksWithoutFindings(pe);

  assert.doesNotMatch(html, /<li>UPX executable packer<\/li>/);
  assert.match(html, /<li>Inno Setup installer<\/li>/);
});

void test("lists undetected resources alongside diagnostics and omits detected sanitizers", () => {
  const pe = sanitizerPe();
  pe.embeddedResources = { bundles: [], issues: ["Could not decode named resource"] };
  pe.sanitizerEvidence = [{ tool: "ASan", kind: "dependency", name: "runtime",
    source: "PE import DLL" }];

  const html = renderChecksWithoutFindings(pe);

  assert.doesNotMatch(html, /<li>ASan<\/li>/);
  assert.match(html, /<li>Qt RCC<\/li>/);
  assert.match(html, /<li>GLib GResource<\/li>/);
  assert.match(html, /<li>UBSan<\/li>/);
});

void test("lists GResource independently when Qt resources are present", async () => {
  const pe = sanitizerPe();
  const { bytes } = minimalRcc();
  pe.embeddedResources = await detectEmbeddedResources(new MockFile(bytes),
    [{ name: ".data", offset: 0, size: bytes.length }], []);

  const html = renderChecksWithoutFindings(pe);

  assert.doesNotMatch(html, /<li>Qt RCC<\/li>/);
  assert.match(html, /<li>GLib GResource<\/li>/);
});

void test("lists undetected ELF NativeAOT, DWARF and Go metadata as separate checks", () => {
  const html = renderChecksWithoutFindings(sanitizerElf());

  assert.match(html, /<li>NativeAOT<\/li>/);
  assert.match(html, /<li>DWARF debug information<\/li>/);
  assert.match(html, /<li>Go build information<\/li>/);
  assert.match(html, /Some checks use heuristics/);
  assert.doesNotMatch(html, /<li>ReadyToRun<\/li>|<li>Go runtime metadata<\/li>/);
});

void test("found ELF metadata does not appear among undetected features", async () => {
  const [elf, dwarf] = await Promise.all([
    parseElf(createElfNativeAotFixture().file), parseElf(createElfDwarfFile())
  ]);
  assert.ok(elf?.nativeAot);
  assert.ok(dwarf?.dwarf);

  assert.doesNotMatch(renderChecksWithoutFindings(elf), /<li>NativeAOT<\/li>/);
  assert.doesNotMatch(renderChecksWithoutFindings(dwarf), /<li>DWARF debug information<\/li>/);
  dwarf.goBuildInfo = { version: "go1.20", moduleInfo: "module sample" };
  assert.doesNotMatch(renderChecksWithoutFindings(dwarf), /<li>Go build information<\/li>/);
  const complete = sanitizerElf();
  complete.nativeAot = elf.nativeAot;
  complete.dwarf = dwarf.dwarf;
  complete.goBuildInfo = dwarf.goBuildInfo;
  assert.equal(renderChecksWithoutFindings(complete), "");
});
