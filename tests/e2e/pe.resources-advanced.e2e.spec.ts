import { expect, test } from "@playwright/test";
import type { Page } from "@playwright/test";
import { createPeResourcePreviewFile } from "../fixtures/pe-resource-preview-file.js";
import { buildResourceSection } from "../fixtures/pe-resource-preview-section.js";
import { createPeResourceSpecs } from "../fixtures/pe-resource-preview-payloads.js";
import { createAdvancedResourcePayloads } from "../fixtures/pe-resource-advanced-payloads.js";
import { createInteractiveResourcePayloads } from "../fixtures/pe-resource-interactive-payloads.js";

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
    ...createPeResourceSpecs(), ...advancedPayloads(), ...createInteractiveResourcePayloads()
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
  await expect(raw.locator(".peDfm__form")).toBeVisible();
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
