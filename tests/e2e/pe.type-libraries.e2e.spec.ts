import { toggleInspectionSection, expandInspectionCollection } from "./inspection-navigation.js";
import { expect, test } from "@playwright/test";
import { createPeTypeLibraryFile } from "../fixtures/pe-type-library-file.js";

void test("TYPELIB analysis mounts through its resource link and restores expanded types", async ({ page }) => {
  const file = createPeTypeLibraryFile();
  await page.goto("/");
  await page.setInputFiles("#fileInput", { name: file.name,
    mimeType: "application/octet-stream", buffer: Buffer.from(file.data) });
  const section = page.locator("#pe-type-libraries");
  const body = section.locator("[data-pe-lazy-section-body]");
  await expect(section).toBeAttached();
  await expect(body).toHaveJSProperty("childElementCount", 0);
  const resources = page.locator('[data-pe-lazy-section="resources"]');
  await toggleInspectionSection(resources.locator(":scope > details > summary"));
  const group = resources.locator("[data-pe-resource-group]").filter({
    has: page.locator(".collectionSummary", { hasText: /^TYPELIB\b/ })
  }).last();
  await expandInspectionCollection(group);
  await group.getByRole("link", { name: "Detailed analysis in Type libraries (COM)." }).first().click();
  await expect(section.locator(":scope > details")).toHaveJSProperty("open", true);
  await expect(body).toContainText("Imported libraries");
  await expect(body).toContainText("SLTG");
  const type = body.locator("details").filter({
    has: page.locator("summary", { hasText: /^interface ITest/ })
  }).first();
  await toggleInspectionSection(type.locator(":scope > summary"));
  await expect(type).toContainText("Run");
  await toggleInspectionSection(section.locator(":scope > details > summary"));
  await expect(body).toHaveJSProperty("childElementCount", 0);
  await toggleInspectionSection(section.locator(":scope > details > summary"));
  await expect(type).toHaveJSProperty("open", true);
});
