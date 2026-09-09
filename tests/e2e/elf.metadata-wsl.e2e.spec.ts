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
  await versions.locator("summary").first().click();
  await expect(versions).toContainText("GLIBC_2.2.5");
  const notes = page.locator("#analysisValue > section").filter({
    has: page.locator(".peSectionSummary", { hasText: /^Notes$/ })
  });
  await notes.locator("summary").first().click();
  await expect(notes).toContainText("Compatible with: IBT, SHSTK");
  const unwind = page.locator("#analysisValue > section").filter({
    has: page.locator(".peSectionSummary", { hasText: "call frame information" })
  });
  await unwind.locator("summary").first().click();
  await expect(unwind).toContainText("FDE offset");
  await expect(unwind).toContainText("zR");
  const instructionDetails = unwind.locator("details").filter({
    has: page.locator(":scope > summary", { hasText: /\d+ instructions/ })
  }).first();
  await instructionDetails.locator("summary").click();
  await expect(instructionDetails).toContainText("def_cfa");
});
