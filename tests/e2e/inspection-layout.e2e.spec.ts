import { expect, test, type Page } from "@playwright/test";
import { createZipWithEntries } from "../fixtures/zip-fixtures.js";
import { createPeResourcePreviewFile } from "../fixtures/pe-resource-preview-file.js";
import { openInspectionSection } from "./inspection-navigation.js";

const expandFileDetails = async (page: Page): Promise<void> => {
  if (!await page.locator("#fileDetails").evaluate(element => element.hasAttribute("open"))) {
    await page.locator("#fileDetails > summary").click();
  }
};

const collapseNarrowFileDetails = async (page: Page): Promise<void> => {
  if (page.viewportSize()!.width < 1280) await page.locator("#fileDetails > summary").click();
};

test("short reports show all structures and return from search and hashes", async ({ page }) => {
  await page.goto("/");
  const file = createZipWithEntries();
  await page.setInputFiles("#fileInput", { name: file.name, mimeType: file.type,
    buffer: Buffer.from(file.data) });
  await expect(page.locator(".workspaceContinuous")).toBeVisible();
  await expect(page.locator("#workspaceNavigation")).toBeHidden();
  await expect(page.getByRole("heading", { name: "ZIP overview" })).toBeVisible();
  await expect(page.getByRole("heading", { name: "End of central directory" })).toBeVisible();
  await expect(page.getByRole("heading", { name: "Central directory entries" })).toBeVisible();
  await openInspectionSection(page, "File hashes");
  await page.getByRole("button", { name: "Back to report" }).click();
  await expect(page.locator(".zipExtractButton").first()).toBeVisible();
  await page.locator("#workspaceFilter").fill("stored.txt");
  await expect(page.locator("#reportSearchResults mark")).toHaveText("stored.txt");
  await page.getByRole("button", { name: "Back to report" }).click();
  await expect(page.locator("#workspaceFilter")).toHaveValue("");
  await expect(page.locator(".zipExtractButton").first()).toBeVisible();
});

test("a long table keeps navigation even with only three sections", async ({ page }) => {
  await page.goto("/");
  const file = createZipWithEntries(Array.from({ length: 50 }, (_, index) => ({
    name: `entry-${index}`, method: 0, data: new Uint8Array([index])
  })));
  await page.setInputFiles("#fileInput", { name: file.name, mimeType: file.type,
    buffer: Buffer.from(file.data) });
  await expect(page.locator("#fileAnalysisDurationDetail")).not.toHaveText("");
  await expect(page.locator(".workspaceContinuous")).toHaveCount(0);
  await expect(page.locator("#workspaceNavigation")).toBeVisible();
});

for (const colorScheme of ["dark", "light"] as const) {
  for (const width of [320, 768, 1440]) {
    test(`file details and navigation fit ${width}px in ${colorScheme}`, async ({ page }) => {
      await page.emulateMedia({ colorScheme });
      await page.setViewportSize({ width, height: 900 });
      await page.goto("/");
      const file = createPeResourcePreviewFile();
      await page.setInputFiles("#fileInput", { name: file.name, mimeType: file.type,
        buffer: Buffer.from(file.data) });
      await expect(page.locator("#workspaceTitle")).toHaveText("Overview");
      await expandFileDetails(page);
      await expect(page.locator("#fileIcon")).toBeVisible();
      await expect(page.locator("#fileMimeTypeDetail")).not.toHaveText("");
      await collapseNarrowFileDetails(page);
      const section = page.locator("#workspaceNavigation button").filter({
        has: page.getByText("Resources", { exact: true })
      });
      await page.locator("#workspaceCards button").filter({
        has: page.getByText("Resources", { exact: true })
      }).focus();
      await page.keyboard.press("Enter");
      await expect(section).toHaveAttribute("aria-current", "page");
      await expect(page.locator("#workspaceTitle")).toHaveText("Resources");
      expect(await section.evaluate(element => element.getBoundingClientRect().height))
        .toBeGreaterThanOrEqual(44);
      expect(await page.locator("html").evaluate(element => element.scrollWidth))
        .toBeLessThanOrEqual(width);
    });
  }
}
