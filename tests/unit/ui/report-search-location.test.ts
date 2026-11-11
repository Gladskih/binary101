import assert from "node:assert/strict";
import { test } from "node:test";
import { reportSearchSection } from "../../../ui/report-search-location.js";

const sections = [
  { key: "analysis-exports", title: "Exports", origin: undefined },
  { key: "analysis-symbols-2", title: "Symbols", origin: undefined },
  { key: "analysis-header", title: "Header", origin: undefined },
  { key: "analysis-preview", title: "Preview", origin: undefined },
  { key: "analysis-tool", title: "Tool", origin: "supplemental" as const }
];

void test("report search maps PE fields and indexed ELF tables to their own sections", () => {
  assert.equal(reportSearchSection("pe", { path: ["exports", "entries", 250, "names", 0], value: "name" },
    sections), "analysis-exports");
  assert.equal(reportSearchSection("elf", { path: ["symbolTables", 2, "symbols", 0], value: "name" },
    sections), "analysis-symbols-2");
  assert.equal(reportSearchSection("elf", { path: ["header", "machineName"], value: "machine" },
    sections), "analysis-header");
});

void test("report search does not link absent sections or unmapped executable data", () => {
  assert.equal(reportSearchSection("pe", { path: ["imports"], value: "name" }, sections), null);
  assert.equal(reportSearchSection("pe", { path: ["unmapped"], value: "name" }, sections), null);
  assert.equal(reportSearchSection("elf", { path: ["symbolTables", "invalid"], value: "name" }, sections), null);
  assert.equal(reportSearchSection("elf", { path: [], value: "name" }, sections), null);
});

void test("other formats prefer structural content and never jump to previews or tools", () => {
  assert.equal(reportSearchSection("png", { path: ["ihdr"], value: "color" }, sections), null);
  assert.equal(reportSearchSection("png", { path: ["ihdr"], value: "color" }, sections.slice(2)),
    "analysis-header");
  assert.equal(reportSearchSection(null, { path: [], value: "name" }, []), null);
  assert.equal(reportSearchSection("png", { path: [], value: "name" }, sections.slice(3)), null);
});
