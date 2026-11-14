import assert from "node:assert/strict";
import { test } from "node:test";
import { initialWorkspaceSection } from "../../../ui/workspace-initial-section.js";

const section = (key: string, title = key) => ({ key, title, origin: undefined });

void test("PE opens PE/COFF headers while preserving the original section order", () => {
  const sections = [section("analysis-dos-header"), section("analysis-pe-headers"), section("analysis-imports")];

  assert.equal(initialWorkspaceSection(sections, "pe"), "analysis-pe-headers");
  assert.equal(sections[0]!.key, "analysis-dos-header");
});

void test("ELF opens its header ahead of instruction-set analysis", () => {
  const sections = [{ ...section("analysis-instruction-sets"), origin: "supplemental" as const },
    section("analysis-header", "ELF header"), section("analysis-linking")];

  assert.equal(initialWorkspaceSection(sections, "elf"), "analysis-header");
});

void test("header preference is format-specific and takes precedence over a preview", () => {
  const sections = [section("preview", "Preview"), section("analysis-header"), section("analysis-pe-headers")];

  assert.equal(initialWorkspaceSection(sections, "pe"), "analysis-pe-headers");
  assert.equal(initialWorkspaceSection(sections, "elf"), "analysis-header");
  assert.equal(initialWorkspaceSection(sections, "png"), "preview");
});

void test("other formats and missing headers prefer previews then format structures", () => {
  const sections = [{ ...section("extra"), origin: "supplemental" as const }, section("structure")];

  assert.equal(initialWorkspaceSection([section("preview", "Preview"), ...sections], "pe"), "preview");
  assert.equal(initialWorkspaceSection([section("metadata"), section("preview", "Preview")], "webm"), "preview");
  assert.equal(initialWorkspaceSection(sections, "elf"), "structure");
  assert.equal(initialWorkspaceSection(sections, null), "structure");
  assert.equal(initialWorkspaceSection(sections, undefined), "structure");
});

void test("supplemental-only and unsupported reports still have an initial view", () => {
  const supplemental = [{ ...section("extra"), origin: "supplemental" as const }];

  assert.equal(initialWorkspaceSection(supplemental, "elf"), "extra");
  assert.equal(initialWorkspaceSection([], "pe"), "hashes");
});
