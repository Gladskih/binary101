import { expect, test } from "@playwright/test";
import type { Page } from "@playwright/test";
import { createPeResourcePreviewFile } from "../fixtures/pe-resource-preview-file.js";
import { buildResourceSection } from "../fixtures/pe-resource-preview-section.js";
import { createPeResourceSpecs } from "../fixtures/pe-resource-preview-payloads.js";
import { createAdvancedResourcePayloads } from "../fixtures/pe-resource-advanced-payloads.js";
import { createInteractiveResourcePayloads } from "../fixtures/pe-resource-interactive-payloads.js";
import { createNotebookDfmResource } from "../fixtures/pe-resource-dfm-payloads.js";

const openGroup = async (page: Page, name: string) => {
  const details = page.locator("[data-pe-resource-group]").filter({
    has: page.locator(":scope > summary", { hasText: new RegExp(`^${name}\\b`) }) }).first();
  await details.locator(":scope > summary").click();
  return details;
};

const advancedPayloads = () => createAdvancedResourcePayloads().map(spec => spec.entryId !== 305 ? spec : {
  ...spec, data: new TextEncoder().encode('<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100" '+
    'onload="globalThis.__peResourceExecuted=true"><rect width="100" height="100" fill="red"/>'+
    '<script>globalThis.__peResourceExecuted=true</script><style>@import url(https://resource-preview.invalid/css);</style>'+
    '<image href="https://resource-preview.invalid/image"/><foreignObject><iframe '+
    'xmlns="http://www.w3.org/1999/xhtml" src="https://resource-preview.invalid/frame"/></foreignObject></svg>')
});

const loadResources = async (page: Page): Promise<void> => {
  const file = createPeResourcePreviewFile(buildResourceSection([
    ...createPeResourceSpecs(), ...advancedPayloads(), ...createInteractiveResourcePayloads(),
    { typeId: 10, entryId: 307, langId: 1033, codePage: 65001,
      data: new TextEncoder().encode(createNotebookDfmResource()) }
  ]));
  await page.goto("/");
  await page.setInputFiles("#fileInput", { name: file.name, mimeType: file.type, buffer: Buffer.from(file.data) });
  await page.locator("[data-pe-lazy-section='resources'] > details > summary").click();
};

test("dialog geometry, initial strings, layout, selection and resource navigation", async ({ page }) => {
  await loadResources(page);
  const group = await openGroup(page, "DIALOG");
  const dialog = group.locator("[data-pe-dialog]").filter({ hasText: "Resource dialog" });
  await expect(dialog).toHaveAttribute("data-pe-dialog-ready", "true");
  await expect(dialog).toContainText("One");
  await expect(dialog).toContainText("Two");
  const control = dialog.locator('[data-pe-dialog-control="3"]');
  await control.click();
  await expect(dialog.locator('[data-pe-dialog-property="3"]')).toHaveClass(/selected/);
  const before = await control.boundingBox();
  await dialog.locator("[data-pe-dialog-client]").evaluate(element => {
    element.style.width = `${element.clientWidth + 80}px`;
    element.style.height = `${element.clientHeight + 40}px`;
  });
  await expect.poll(async () => (await control.boundingBox())!.x - before!.x).toBeCloseTo(80, 0);
  await group.locator(".peResourceConnections").last().locator(":scope > summary").click();
  await group.locator(".peResourceConnections").last().locator("a").first().click();
  await expect(page.locator('[data-pe-resource-group][open]').first()).toBeVisible();
});

test("renders Ribbon tabs, DFM, vector drawings and an animated cursor", async ({ page }) => {
  const externalRequests: string[] = [];
  page.on("request", request => {
    if (request.url().includes("resource-preview.invalid")) externalRequests.push(request.url());
  });
  await loadResources(page);
  const ribbon = await openGroup(page, "RIBBON_XML");
  await ribbon.getByRole("tab", { name: "View", exact: true }).click();
  await expect(ribbon.locator('[data-pe-ribbon-panel]:visible')).toContainText("Scale");
  const raw = await openGroup(page, "RCDATA");
  await expect(raw.locator('.peDfm__form[data-pe-dfm-component="Main"]')).toBeVisible();
  await expect(raw.locator(".peVector svg")).toHaveCount(3);
  await expect(raw.locator(".peVector script,.peVector image,.peVector foreignObject")).toHaveCount(0);
  const animation = await openGroup(page, "ANICURSOR");
  const player = animation.locator("[data-pe-animation]").last();
  await player.locator("[data-pe-animation-play]").click();
  await expect(player.locator("[data-pe-animation-status]")).toContainText("Step");
  await player.locator("[data-pe-animation-play]").click();
  await expect(player.locator("[data-pe-animation-status]")).toContainText("Stopped");
  await page.waitForLoadState("networkidle");
  expect(externalRequests).toEqual([]);
  expect(await page.evaluate(() => "__peResourceExecuted" in globalThis)).toBe(false);
  await ribbon.screenshot({ path: "reports/pe-resource-ribbon.png" });
  await page.screenshot({ path: "reports/pe-resource-previews.png", fullPage: true });
});

test("DFM pages inherit bounds and fonts, hide inactive content and draw native progress", async ({ page }) => {
  await loadResources(page);
  const raw = await openGroup(page, "RCDATA");
  const form = raw.locator('.peDfm__form[data-pe-dfm-component="NotebookPreview"]');
  const notebook = form.locator('[data-pe-dfm-component="Pages"]');
  const active = notebook.locator(':scope > [data-pe-dfm-component="Installing"]');
  await expect(active).toHaveCSS("width", "389px");
  await expect(active).toHaveCSS("height", "170px");
  await expect(active).toHaveCSS("border-top-width", "0px");
  await expect(active).toHaveCSS("font-size", "11px");
  await expect(form.locator('[data-pe-dfm-component="Other"]')).toBeHidden();
  await expect(form.locator('[data-pe-dfm-component="HiddenText"]')).toBeHidden();
  await expect(form.locator('[data-pe-dfm-component="HiddenLabel"]')).toBeHidden();
  const progress = active.locator('[data-pe-dfm-component="Progress"]');
  await expect(progress.locator("progress")).toHaveAttribute("value", "150");
  await expect(progress.locator("progress")).toHaveAttribute("max", "300");
  const parentBox = (await active.boundingBox())!;
  const progressBox = (await progress.boundingBox())!;
  expect(progressBox.x - parentBox.x).toBe(36);
  expect(progressBox.y - parentBox.y).toBe(56);
  await expect(active.locator('[data-pe-dfm-component="Status"]')).toHaveText("*");
  const path = form.locator('[data-pe-dfm-component="PathEdit"]');
  await expect(path).toHaveClass(/peDfm__control--edit/);
  await expect(path).toHaveText("Saved path");
  await expect(path).toHaveCSS("border-top-width", "1px");
  const license = active.locator('[data-pe-dfm-component="License"]');
  await expect(license).toHaveClass(/peDfm__control--memo/);
  await expect(license).toHaveText("License text\nSecond line");
  await expect(license).toHaveCSS("white-space", "pre");
  await expect(license).toHaveCSS("border-top-width", "0px");
  const evidence = raw.locator(".peDfm + table").filter({ hasText: "NotebookPreview" });
  await expect(evidence.locator("thead th")).toHaveText(["Component", "Class", "Saved properties"]);
  await expect(evidence.locator("tbody > tr")).toHaveCount(10);
  await expect(evidence).toContainText("NotebookPreview.Pages.Other.HiddenText");
});
