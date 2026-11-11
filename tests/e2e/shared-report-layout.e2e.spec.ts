import { expect, test } from "@playwright/test";
import { createPngFile } from "../fixtures/image-sample-files.js";
import { createPePlusFile } from "../fixtures/sample-files-pe.js";
import { openInspectionSection } from "./inspection-navigation.js";

test("plain PNG tables share the grid and the workspace has no outer card gutter", async ({ page }) => {
  const file = createPngFile();
  await page.setViewportSize({ width: 1920, height: 1000 });
  await page.goto("/");
  await page.setInputFiles("#fileInput", { name: file.name, mimeType: file.type,
    buffer: Buffer.from(file.data) });
  await expect(page.locator("#workspaceTitle")).toHaveText("Preview");
  await openInspectionSection(page, "Chunks");
  const table = page.locator("#analysisValue table:visible").first();
  await expect(table.locator("tbody td").first()).toHaveCSS("border-right-width", "1px");
  await expect(table.locator("tbody td").first()).toHaveCSS("border-bottom-width", "1px");
  await expect(table.locator("tbody td").first()).toHaveCSS("padding-left", "10px");
  const bounds = await page.locator("#fileInfoCard").boundingBox();
  expect(bounds!.x).toBe(0);
  expect(bounds!.width).toBe(1920);
  await expect(page.locator("#fileInfoCard")).toHaveCSS("border-radius", "0px");
  expect((await table.boundingBox())!.width).toBeLessThan(700);
});

test("entropy action keeps workspace position and button width through completion", async ({ page }) => {
  const file = createPePlusFile();
  await page.goto("/");
  await page.setInputFiles("#fileInput", { name: file.name, mimeType: file.type,
    buffer: Buffer.from(file.data) });
  await openInspectionSection(page, "Section headers");
  const button = page.locator("[data-section-entropy-action]");
  const before = await button.boundingBox();
  const top = (await page.locator("#fileInfoCard").boundingBox())!.y;
  await button.click();
  await expect(button).toHaveText("Entropy calculated");
  await expect(button).toBeDisabled();
  expect((await page.locator("#fileInfoCard").boundingBox())!.y).toBe(top);
  expect((await button.boundingBox())!.width).toBe(before!.width);
  expect((await page.locator("#statusMessage").boundingBox())!.height).toBe(0);
  await openInspectionSection(page, "File hashes");
  await openInspectionSection(page, "Section headers");
  await expect(button).toBeDisabled();
  await expect(button).toHaveText("Entropy calculated");
});

test("text cells and text blocks have a reading measure on a wide viewport", async ({ page }) => {
  await page.goto("/");
  await page.locator("main").evaluate(main => {
    const sample = main.ownerDocument.createElement("article");
    sample.id = "readingMeasureSample";
    const words = "A sentence with several words. ".repeat(30);
    sample.innerHTML = `<p>${words}</p><div class="smallNote">${words}</div>` +
      `<table><tbody><tr><td>${words}</td></tr></tbody></table>`;
    main.append(sample);
  });
  await page.setViewportSize({ width: 2530, height: 1000 });
  const widths = await page.locator("#readingMeasureSample :is(p,.smallNote,td)")
    .evaluateAll(elements => elements.map(element => element.getBoundingClientRect().width));
  expect(widths).toHaveLength(3);
  for (const width of widths) expect(width).toBeLessThan(900);
});
