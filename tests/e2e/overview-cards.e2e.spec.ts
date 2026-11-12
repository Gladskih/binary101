import { expect, test } from "@playwright/test";
import { createPeResourcePreviewFile } from "../fixtures/pe-resource-preview-file.js";
import { createPePlusFile } from "../fixtures/sample-files-pe.js";
import { openInspectionSection } from "./inspection-navigation.js";

test("PE overview previews native destinations without mounting the detail panels", async ({ page }) => {
  await page.setViewportSize({ width: 1440, height: 900 });
  await page.goto("/");
  const file = createPeResourcePreviewFile();
  await page.setInputFiles("#fileInput", { name: file.name, mimeType: file.type,
    buffer: Buffer.from(file.data) });
  await expect(page.locator("#workspaceTitle")).toHaveText("Overview");
  await expect(page.locator("#workspaceNavigation")).toBeHidden();
  await expect(page.locator(".workspaceSidebar")).toBeHidden();
  const headers = page.locator(".workspaceCard").filter({
    has: page.getByRole("button", { name: "PE/COFF headers", exact: true })
  });
  await expect(headers).toContainText("COFF.Machine");
  await expect(headers).toContainText("0x8664");
  await expect(page.locator(".overviewMedia img").first()).toBeVisible();
  await expect(page.locator("#analysisValue .peSectionBody table")).toHaveCount(0);
  await expect(page.locator("#fileOverviewContent")).not.toContainText("PointerToRawData");
  await headers.getByRole("button").click();
  await expect(page.locator("#workspaceTitle")).toHaveText("PE/COFF headers");
  await expect(page.locator("#workspaceNavigation")).toBeVisible();
  await page.locator("#workspaceReportButton").click();
  await expect(page.locator("#workspaceOverview")).toBeVisible();
  await expect(page.locator("#fileIcon")).toBeVisible();
});

test("PE files without VERSION metadata still start with source previews", async ({ page }) => {
  await page.goto("/");
  const file = createPePlusFile();
  await page.setInputFiles("#fileInput", { name: file.name, mimeType: file.type,
    buffer: Buffer.from(file.data) });
  await expect(page.locator("#workspaceTitle")).toHaveText("Overview");
  await expect(page.locator("#workspaceCards")).toContainText("COFF.Machine");
  await expect(page.locator("#fileOverviewContent")).not.toContainText("SizeOfRawData");
  await openInspectionSection(page, "Section headers");
  await expect(page.locator("#workspaceTitle")).toHaveText("Section headers");
});
