import { expect, test } from "@playwright/test";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  buildPagedDRuntimeProgram, D_TEST_PAGE_SIZE, hasWindowsDCompiler
} from "../fixtures/d-runtime-program.js";

test("D runtime module and reference tables work in the browser", async ({ page }) => {
  test.skip(!(await hasWindowsDCompiler()), "Requires Windows DMD");
  const directory = await mkdtemp(join(tmpdir(), "binary101-d-runtime-ui-"));
  try {
    await page.goto("/");
    await page.setInputFiles("#fileInput", { buffer: await buildPagedDRuntimeProgram(directory),
      name: "sample.exe", mimeType: "application/octet-stream" });
    const section = page.locator("section.peSection").filter({
      has: page.locator("summary", { hasText: "D runtime metadata" })
    });
    await section.locator("summary").click();
    const modules = section.locator('[data-paged-sortable-table-id="pe-d-runtime-modules"]');
    await expect(modules).toContainText("sample");
    await expect(modules.locator("tbody tr")).toHaveCount(D_TEST_PAGE_SIZE);
    await modules.getByRole("button", { name: "Next", exact: true }).click();
    await expect(modules).toContainText(`Showing ${D_TEST_PAGE_SIZE + 1}-`);
    await modules.getByRole("button", { name: "First", exact: true }).click();
    await modules.getByRole("button", { name: "Sort by Module", exact: true }).click();
    await expect(modules.locator("tbody tr").first().locator("td").first())
      .toContainText("core.");
    await expect(section.locator('[data-sort-state-key="pe-d-runtime-references"], ' +
      '[data-paged-sortable-table-id="pe-d-runtime-references"]'))
      .toContainText("Local ClassInfo reference");
    await expect(section).not.toContainText("Invalid or unsupported");
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});
