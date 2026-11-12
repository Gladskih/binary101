import { expect, test, type Page } from "@playwright/test";
import { createPeResourcePreviewFile } from "../fixtures/pe-resource-preview-file.js";
import { openInspectionSection } from "./inspection-navigation.js";

const inspectPe = async (page: Page): Promise<void> => {
  const file = createPeResourcePreviewFile();
  await page.goto("/");
  await page.setInputFiles("#fileInput", { name: file.name, mimeType: file.type,
    buffer: Buffer.from(file.data) });
  await expect(page.locator("#workspaceTitle")).toHaveText("Overview");
};

test("native overview retains the icon, source fields and header properties", async ({ page }) => {
  await inspectPe(page);
  await expect(page.locator("#fileIcon")).toBeVisible();
  await expect(page.locator("#fileOverviewContent")).toContainText("VERSION / 1 / LANGID 0x0409");
  await expect(page.locator("#fileOverviewContent")).toContainText("FileDescription");
  await expect(page.locator("#fileOverviewContent")).not.toContainText("Architecture");
  await page.locator('[data-workspace-source="resources"]').click();
  await expect(page.locator('[data-pe-lazy-section="resources"]')).toBeVisible();
  await expect(page.locator("#workspaceNavigation")).not.toContainText("File hashes");
  await expect(page.locator("#fileFormatSummary")).toHaveCount(0);
  await expect(page.locator("#fileDetails #fileMimeTypeDetail")).toBeVisible();
  await expect(page.locator("#fileDetails #fileTimestampDetail")).toBeVisible();
  await expect(page.locator("#fileDetails #fileAnalysisDurationDetail")).toBeVisible();
  await expect(page.locator("#fileSourceDetail .opt.sel")).toHaveText("Selection");
  await expect(page.locator("#fileObjectDetail .opt.sel")).toHaveText("File");
  expect(await page.title()).toContain(createPeResourcePreviewFile().name);
});

test("file hashes remain a header tool with no outer frame or disclosure", async ({ page }) => {
  await inspectPe(page);
  await openInspectionSection(page, "File hashes");
  await expect(page.locator("#fileIcon")).toBeVisible();
  await expect(page.locator("#hashDetails summary")).toHaveCount(0);
  await expect(page.locator("#md5ComputeButton")).toBeVisible();
  await expect(page.locator("#hashDetails")).toHaveCSS("border-top-width", "0px");
});

test("wide screen uses one row for file properties and actions", async ({ page }) => {
  // Leave room for a complete row across different system font metrics.
  await page.setViewportSize({ width: 3200, height: 1000 });
  await inspectPe(page);
  expect(await page.locator(".appHeader").evaluate(element => element.getBoundingClientRect().height))
    .toBeLessThanOrEqual(50);
  await expect(page.locator('.appHeader a[href*="github.com"]')).toBeVisible();
  const baselines = await page.locator(".appHeader").evaluate(header =>
    Array.from(header.querySelectorAll(
      "#fileNameDetail,#fileBinaryTypeDetail,#fileSizeDetail,.fileProperty dt," +
      ".fileProperty dd:not(:has(.opt)),.fileProperty .opt.sel"
    )).filter(element => element.getClientRects().length).map(element => {
      const marker = element.ownerDocument.createElement("span");
      marker.style.cssText = "display:inline-block;width:0;height:0;vertical-align:baseline";
      element.append(marker);
      const baseline = marker.getBoundingClientRect().y;
      marker.remove();
      return baseline;
    }));
  expect(Math.max(...baselines) - Math.min(...baselines)).toBeLessThan(1);
  await expect(page.locator("#fileBinaryTypeDetail")).toHaveCSS("border-left-width", "1px");
  await expect(page.locator("#fileSizeDetail")).toHaveCSS("border-left-width", "1px");
});

for (const width of [320, 500, 768]) {
  test(`header and navigation fit a ${width}px viewport`, async ({ page }) => {
    await page.setViewportSize({ width, height: 900 });
    await inspectPe(page);
    await expect(page.locator("#workspaceNavigation")).toBeVisible();
    await expect(page.locator("#workspaceFilter")).toBeVisible();
    const sectionBox = await page.locator("#workspaceNavigation").boundingBox();
    const searchBox = await page.locator(".workspaceSidebar__search").boundingBox();
    expect(sectionBox!.y - searchBox!.y - searchBox!.height).toBeGreaterThanOrEqual(0);
    await expect(page.locator("#fileProperties")).toBeHidden();
    await page.locator("#fileDetails > summary").click();
    await expect(page.locator("#fileProperties")).toBeVisible();
    await page.locator("#fileDetails > summary").click();
    expect(await page.locator("html").evaluate(element => element.scrollWidth)).toBeLessThanOrEqual(width);
    await openInspectionSection(page, "Data directories");
    await expect(page.locator('[data-pe-lazy-section="data-directories"]')).toBeVisible();
  });
}

test("narrow header aligns wrapped actions with file identity", async ({ page }) => {
  await page.setViewportSize({ width: 500, height: 900 });
  await inspectPe(page);
  const title = await page.locator("#fileNameDetail").boundingBox();
  const actions = await page.locator(".appHeader__actions").boundingBox();
  expect(actions!.x).toBeCloseTo(title!.x, 0);
  expect(actions!.y).toBeGreaterThan(title!.y + title!.height);
});

test("table frames and introductions remain separate", async ({ page }) => {
  await inspectPe(page);
  await openInspectionSection(page, "Data directories");
  const table = page.locator('[data-pe-lazy-section="data-directories"] table').first();
  expect(await table.evaluate(element => Number.parseFloat(
    element.ownerDocument.defaultView!.getComputedStyle(element).borderTopWidth))).toBeGreaterThan(0);
  expect(await table.evaluate(element => element.getBoundingClientRect().top -
    element.closest('.tableWrap')!.previousElementSibling!.getBoundingClientRect().bottom))
    .toBeGreaterThanOrEqual(10);
});

test("welcome never displays empty file properties or file tools", async ({ page }) => {
  await page.goto("/");
  await expect(page.locator("#fileProperties")).toBeHidden();
  await expect(page.locator("#fileHashesButton")).toBeHidden();
  await expect(page.locator("#dropZone")).toBeVisible();
});

test("analysis navigation has one separator without a padded background strip", async ({ page }) => {
  await inspectPe(page);
  await expect(page.locator(".workspaceAnalysis")).toHaveCSS("padding-top", "0px");
  await expect(page.locator(".workspaceAnalysis")).toHaveCSS("background-color", "rgba(0, 0, 0, 0)");
});
