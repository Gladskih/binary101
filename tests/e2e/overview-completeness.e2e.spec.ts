import { expect, test } from "@playwright/test";
import { createPeResourcePreviewFile } from "../fixtures/pe-resource-preview-file.js";
import { buildResourceSection } from "../fixtures/pe-resource-preview-section.js";
import { createPeResourceSpecs } from "../fixtures/pe-resource-preview-payloads.js";

test("a Resources tile highlights VERSION metadata and opens both full resource variants", async ({ page }) => {
  await page.setViewportSize({ width: 2530, height: 900 });
  await page.goto("/");
  // RT_VERSION is resource type 16. Two IDs must remain in the detailed tree.
  const version = createPeResourceSpecs().find(resource => resource.typeId === 16)!;
  const file = createPeResourcePreviewFile(buildResourceSection([
    version, { ...version, entryId: version.entryId + 1 }
  ]));
  await page.setInputFiles("#fileInput", { name: file.name, mimeType: file.type,
    buffer: Buffer.from(file.data) });
  const card = page.getByRole("button", { name: "Resources", exact: true });
  await expect(card).toContainText("FileDescription");
  await expect(card).toContainText("PE resource showcase");
  await expect(card.locator("table,ul,ol,details")).toHaveCount(0);

  await card.focus();
  await page.keyboard.press("Enter");

  await expect(page.locator("#workspaceTitle")).toHaveText("Resources");
  await expect(page.locator('[data-pe-lazy-section="resources"]')).toContainText("ID 1");
  await expect(page.locator('[data-pe-lazy-section="resources"]')).toContainText("ID 2");
});
