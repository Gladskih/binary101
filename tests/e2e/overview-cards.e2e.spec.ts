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

test("PE overview tiles open native details without mounting them initially", async ({ page }) => {
  await page.setViewportSize({ width: 1440, height: 900 });
  await page.goto("/");
  const file = createPeResourcePreviewFile();
  await page.setInputFiles("#fileInput", { name: file.name, mimeType: file.type,
    buffer: Buffer.from(file.data) });
  await expect(page.locator("#workspaceTitle")).toHaveText("Overview");
  const headers = page.locator("#workspaceOverview").getByRole("button", { name: "PE/COFF headers", exact: true });
  await expect(headers).toContainText("Machine");
  await expect(headers).toContainText("x86-64 (AMD64)");
  await expect(headers).not.toContainText("0x8664");
  await expect(page.locator('.workspaceCard[data-workspace-target="analysis-dos-header"]')).toHaveCount(0);
  await expect(page.locator('.workspaceCard[data-workspace-target="analysis-exports"]')).toHaveCount(0);
  await expect(page.locator(".workspaceCard__image").first()).toBeVisible();
  await expect(page.locator("#workspaceOverview table")).toHaveCount(0);
  await expect(page.locator("#analysisValue .peSectionBody table")).toHaveCount(0);
  await headers.locator(".workspaceCard__body").click();

  await expect(page.locator("#workspaceTitle")).toHaveText("PE/COFF headers");
  await expect(page.locator("#workspaceNavigation")).toBeVisible();
  await openInspectionSection(page, "Overview");
  await expect(page.locator("#workspaceOverview")).toBeVisible();
  await expect(page.locator("#fileIcon")).toBeVisible();
});

test("PE without VERSION metadata still has factual highlights and keyboard navigation", async ({ page }) => {
  await page.goto("/");
  const file = createPePlusFile();
  await page.setInputFiles("#fileInput", { name: file.name, mimeType: file.type,
    buffer: Buffer.from(file.data) });
  await expect(page.locator("#workspaceTitle")).toHaveText("Overview");
  const card = page.locator("#workspaceOverview").getByRole("button", { name: "PE/COFF headers", exact: true });
  await expect(card).toContainText("Machine");

  await card.focus();
  await page.keyboard.press("Space");

  await expect(page.locator("#workspaceTitle")).toHaveText("PE/COFF headers");
});

for (const width of [390, 1440, 1684, 2530]) {
  test(`resource image collections remain one compact tile at ${width}px`, async ({ page }) => {
    await page.setViewportSize({ width, height: 900 });
    await page.goto("/");
    const single = imageResources(1);
    await page.setInputFiles("#fileInput", { name: single.name, mimeType: single.type,
      buffer: Buffer.from(single.data) });
    const resourceCard = page.getByRole("button", { name: "Resources", exact: true });
    await expect(resourceCard).toBeVisible();
    const before = (await resourceCard.boundingBox())!;
    const many = imageResources(40);

    await page.setInputFiles("#fileInput", { name: "many-images.exe", mimeType: many.type,
      buffer: Buffer.from(many.data) });

    await expect(resourceCard.locator("img")).toHaveCount(1);
    const after = (await resourceCard.boundingBox())!;
    expect(after.height).toBe(before.height);
    expect(after.height).toBeLessThan(320);
    await resourceCard.click();
    await expect(page.locator("#workspaceTitle")).toHaveText("Resources");
    await expect(page.locator('[data-pe-lazy-section="resources"]')).toContainText("ID 40");
  });
}
