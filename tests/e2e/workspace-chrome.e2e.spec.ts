import { expect, test, type Page } from "@playwright/test";
import { createPeResourcePreviewFile } from "../fixtures/pe-resource-preview-file.js";
import { createWebmFile } from "../fixtures/webm-base-fixtures.js";
import { openInspectionSection } from "./inspection-navigation.js";

const openPeWithPausedTailScan = async (page: Page): Promise<void> => {
  // Force the PE tail scan to read outside the first cached header window.
  const file = createPeResourcePreviewFile();
  const buffer = Buffer.alloc(512 * 1024, 1);
  Buffer.from(file.data).copy(buffer);
  await page.evaluate(minimumOffset => {
    const slice = File.prototype.slice;
    const ready = new Promise<void>(resolve => {
      globalThis.addEventListener("release-pe-tail", () => resolve(), { once: true });
    });
    File.prototype.slice = function (start, end, type) {
      const part = slice.call(this, start, end, type);
      if ((start ?? 0) < minimumOffset) return part;
      const read = part.arrayBuffer.bind(part);
      part.arrayBuffer = async () => {
        await ready;
        return read();
      };
      return part;
    };
  }, 256 * 1024);
  await page.setInputFiles("#fileInput", { name: file.name, mimeType: file.type, buffer });
};

test("ordinary analysis shows its status before the report is ready", async ({ page }) => {
  await page.emulateMedia({ colorScheme: "dark" });
  await page.setViewportSize({ width: 780, height: 900 });
  await page.goto("/");
  await page.evaluate(() => { globalThis.document.documentElement.style.zoom = "2"; });
  await openPeWithPausedTailScan(page);

  await expect(page.getByRole("status").filter({ hasText: "Parsing file details" })).toBeVisible();
  await expect(page.locator("#workspaceTitle")).toHaveText("Analysis");
  await expect(page.locator("#workspaceHashes")).toBeHidden();
  await page.evaluate(() => { globalThis.dispatchEvent(new Event("release-pe-tail")); });

  await expect(page.locator("#workspaceTitle")).toHaveText("PE/COFF headers");
  await expect(page.locator("#workspaceHashes")).toBeHidden();
  await expect(page.locator("#statusMessage")).toBeEmpty();
});

test("global file actions stay available when properties close and the viewport narrows", async ({ page }) => {
  await page.setViewportSize({ width: 1440, height: 900 });
  await page.goto("/");
  const file = createPeResourcePreviewFile();
  await page.setInputFiles("#fileInput", { name: file.name, mimeType: file.type,
    buffer: Buffer.from(file.data) });
  await expect(page.locator("#workspaceTitle")).toHaveText("PE/COFF headers");
  await page.locator("#fileDetails > summary").click();

  await expect(page.locator("#fileOpenButton")).toBeVisible();
  await expect(page.locator("#fileDetails #fileOpenButton")).toHaveCount(0);
  await page.setViewportSize({ width: 900, height: 900 });
  await expect(page.locator("#fileOpenButton")).toBeVisible();
  await expect(page.locator("#directoryOpenButton")).toBeVisible();
  await expect(page.locator("#fileNameDetail")).toBeVisible();
  await page.setViewportSize({ width: 1440, height: 900 });
  await expect(page.locator("#fileOpenButton")).toBeVisible();
});

test("mobile video preview is independent of file properties and starts in the report", async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto("/");
  const file = createWebmFile();
  await page.setInputFiles("#fileInput", { name: file.name, mimeType: file.type,
    buffer: Buffer.from(file.data) });

  await expect(page.locator("#analysisValue .videoPreview")).toBeVisible();
  await expect(page.locator("#fileDetails .videoPreview")).toHaveCount(0);
  await expect(page.locator("#workspaceTitle")).toHaveText("Preview");
  await page.locator("#fileDetails > summary").click();
  await page.locator("#fileDetails > summary").click();
  await expect(page.locator("#analysisValue .videoPreview")).toBeVisible();
});

test("browser back from a detail view restores the report without clearing the selected file", async ({ page }) => {
  await page.goto("/");
  const file = createPeResourcePreviewFile();
  await page.setInputFiles("#fileInput", { name: file.name, mimeType: file.type,
    buffer: Buffer.from(file.data) });
  await openInspectionSection(page, "File hashes");
  await expect(page.locator("#md5Value")).toHaveText(/^[a-f0-9]{32}$/);
  const hash = await page.locator("#md5Value").textContent();
  await openInspectionSection(page, "PE/COFF headers");
  await openInspectionSection(page, "Resources");

  await page.goBack();

  await expect(page.locator("#fileInfoCard")).toBeVisible();
  await expect(page.locator("#workspaceTitle")).toHaveText("PE/COFF headers");
  await expect(page.locator("#fileNameDetail")).toHaveText(file.name);
  await expect(page.locator("#md5Value")).toHaveText(hash!);
  await page.goForward();
  await expect(page.locator("#workspaceTitle")).toHaveText("Resources");
});

test("back to search restores the phrase and highlighted matches", async ({ page }) => {
  await page.goto("/");
  const file = createPeResourcePreviewFile();
  await page.setInputFiles("#fileInput", { name: file.name, mimeType: file.type,
    buffer: Buffer.from(file.data) });
  await expect(page.locator("#workspaceTitle")).toHaveText("PE/COFF headers");
  await page.locator("#workspaceFilter").fill("Binary101");
  await expect(page.locator("#reportSearchResults mark").first()).toHaveText("Binary101");
  await page.locator("#reportSearchResults .overviewLink").first().click();

  await page.goBack();

  await expect(page.locator("#workspaceTitle")).toHaveText("Search results");
  await expect(page.locator("#workspaceFilter")).toHaveValue("Binary101");
  await expect(page.locator("#reportSearchResults mark").first()).toHaveText("Binary101");
  await expect(page.locator("#fileNameDetail")).toHaveText(file.name);
});
