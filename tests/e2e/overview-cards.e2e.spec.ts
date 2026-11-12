import { expect, test } from "@playwright/test";
import { createPeResourcePreviewFile } from "../fixtures/pe-resource-preview-file.js";
import { createPePlusFile } from "../fixtures/sample-files-pe.js";
import { openInspectionSection } from "./inspection-navigation.js";
import { buildResourceSection } from "../fixtures/pe-resource-preview-section.js";
import { createPeResourceSpecs } from "../fixtures/pe-resource-preview-payloads.js";

const imageResources = (count: number) => {
  const bitmap = createPeResourceSpecs().find(resource => resource.typeId === 2)!;
  return createPeResourcePreviewFile(buildResourceSection(Array.from({ length: count }, (_, index) =>
    ({ ...bitmap, entryId: index + 1 }))));
};

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

for (const width of [390, 1440, 1684, 2530]) {
  test(`many resource images do not push the other overview cards down at ${width}px`, async ({ page }) => {
    await page.setViewportSize({ width, height: 900 });
    await page.goto("/");
    const single = imageResources(1);
    await page.setInputFiles("#fileInput", { name: single.name, mimeType: single.type,
      buffer: Buffer.from(single.data) });
    await expect(page.locator(".overviewMedia")).toHaveCount(1);
    const before = (await page.locator(".workspaceCard").last().boundingBox())!;
    const many = imageResources(40);

    await page.setInputFiles("#fileInput", { name: "many-images.exe", mimeType: many.type,
      buffer: Buffer.from(many.data) });
    await expect(page.locator(".overviewMedia")).toHaveCount(40);
    const after = (await page.locator(".workspaceCard").last().boundingBox())!;
    expect(after.y - before.y).toBeLessThan(32);
    const first = (await page.locator(".overviewMedia").first().boundingBox())!;
    const last = (await page.locator(".overviewMedia").last().boundingBox())!;
    expect(last.y).toBeCloseTo(first.y, 0);
    await page.locator(".overviewGallery").scrollIntoViewIfNeeded();
    await page.locator(".overviewGallery").evaluate(element => { element.scrollLeft = element.scrollWidth; });
    await expect(page.locator(".overviewMedia").last()).toBeInViewport();
    await page.locator(".overviewMedia").last().click();
    await expect(page.locator("#workspaceTitle")).toHaveText("Resources");
  });
}
