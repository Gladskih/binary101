import { toggleInspectionSection } from "./inspection-navigation.js";
import { execFileSync } from "node:child_process";
import { expect, test } from "@playwright/test";
import { probeWslReadelf } from "../external/elf-wsl-readelf-fixtures.js";

test("real WSL ELF shows version suffixes, GNU properties and paged unwind records", async ({ page }) => {
  const probe = probeWslReadelf();
  test.skip(!probe.available, probe.reason);
  const buffer = execFileSync("wsl", ["--exec", "cat", "/lib/x86_64-linux-gnu/libc.so.6"],
    { maxBuffer: 32 * 1024 * 1024 });
  await page.goto("/");
  await page.setInputFiles("#fileInput", { name: "libc.so.6", mimeType: "application/x-elf", buffer });
  const versions = page.locator("#analysisValue > section").filter({
    has: page.locator(".peSectionSummary", { hasText: "Symbol versions" })
  });
  await toggleInspectionSection(versions.locator("summary").first());
  await expect(versions).toContainText("GLIBC_2.2.5");
  const notes = page.locator("#analysisValue > section").filter({
    has: page.locator(".peSectionSummary", { hasText: /^Notes$/ })
  });
  await toggleInspectionSection(notes.locator("summary").first());
  await expect(notes).toContainText("Compatible with: IBT, SHSTK");
  const unwind = page.locator("#analysisValue > section").filter({
    has: page.locator(".peSectionSummary", { hasText: "call frame information" })
  });
  await toggleInspectionSection(unwind.locator("summary").first());
  await expect(unwind).toContainText("FDE offset");
  await expect(unwind).toContainText("zR");
  const instructionDetails = unwind.locator("details").filter({
    has: page.locator(":scope > summary", { hasText: /\d+ instructions/ })
  }).first();
  await toggleInspectionSection(instructionDetails.locator("summary"));
  await expect(instructionDetails).toContainText("def_cfa");
  const rules = unwind.locator("details").filter({
    has: page.locator(":scope > summary", { hasText: /\d+ unwind rule rows/ })
  }).first();
  await toggleInspectionSection(rules.locator("summary"));
  await expect(rules).toContainText("CFA");
  await expect(rules).toContainText(/r7 \+ \(\d+\)/);
  const hashes = page.locator("#analysisValue > section").filter({
    has: page.locator(".peSectionSummary", { hasText: "GNU symbol hash table" })
  });
  await toggleInspectionSection(hashes.locator("summary").first());
  await expect(hashes).toContainText("Bloom shift");
  await expect(hashes.locator("tbody tr")).toHaveCount(100);
});
