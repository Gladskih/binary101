"use strict";

import { expect, test } from "@playwright/test";
import { createPePdataRangeFile } from "../fixtures/pe-pdata-range-file.js";
import { NARROW_LAYOUT_VIEWPORT } from "./viewports.js";

test.beforeEach(async ({ page }) => {
  const file = createPePdataRangeFile();
  await page.goto("/");
  await page.setInputFiles("#fileInput", {
    name: file.name, mimeType: file.type, buffer: Buffer.from(file.data)
  });
  await page.locator('[data-pe-lazy-section="exception"] > details > summary').click();
});

void test("pdata histogram renders parsed byte ranges and survives reopening the lazy section", async ({
  page
}) => {
  const histogram = page.locator(".rangeHistogram");
  const summary = page.locator('[data-pe-lazy-section="exception"] > details > summary');
  await expect(histogram).toContainText("5 measured ranges");
  await expect(histogram).not.toContainText("hover for exact byte intervals");
  await expect(histogram.getByRole("img")).toBeVisible();
  await expect(histogram.locator("svg title")).toHaveText([
    "1 bytes: 1 ranges", "2–3 bytes: 2 ranges", "4–7 bytes: 0 ranges",
    "8–15 bytes: 1 ranges", "16–31 bytes: 1 ranges"
  ]);

  await summary.click();
  await expect(histogram).toHaveCount(0);
  await summary.click();

  await expect(histogram).toContainText("5 measured ranges");
});

void test("pdata histogram scrolls within its panel on a narrow screen", async ({ page }) => {
  await page.setViewportSize(NARROW_LAYOUT_VIEWPORT);
  const histogram = page.locator(".rangeHistogram__scroll");
  await expect(histogram).toBeVisible();

  const widths = await histogram.evaluate(element => ({
    panel: element.clientWidth,
    plot: element.scrollWidth,
    viewport: element.ownerDocument.documentElement.clientWidth,
    page: element.ownerDocument.documentElement.scrollWidth
  }));

  expect(widths.plot).toBeGreaterThan(widths.panel);
  expect(widths.page).toBe(widths.viewport);
  await histogram.scrollIntoViewIfNeeded();
  await histogram.evaluate(element => { element.scrollLeft = element.scrollWidth; });
  await expect(histogram.locator("svg text").filter({ hasText: /^16$/ })).toBeInViewport();
});
