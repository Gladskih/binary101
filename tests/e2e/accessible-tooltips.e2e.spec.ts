"use strict";

import { expect, test } from "@playwright/test";
import { createPePlusFile } from "../fixtures/sample-files-pe.js";

void test("keeps a file-summary tooltip within a phone viewport", async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto("/");
  const file = createPePlusFile();
  await page.setInputFiles("#fileInput", {
    name: file.name,
    mimeType: file.type,
    buffer: Buffer.from(file.data)
  });
  const button = page.locator("#fileBinaryTypeDetail .accessibleTooltipButton");
  await expect(button).toBeVisible();
  await button.click();
  const popup = page.locator("#fileBinaryTypeDetail .accessibleTooltipPopup");
  await expect(popup).toBeVisible();
  const popupBox = await popup.boundingBox();
  const viewport = page.viewportSize();
  expect(popupBox).not.toBeNull();
  expect(viewport).not.toBeNull();
  expect(popupBox!.x).toBeGreaterThanOrEqual(0);
  expect(popupBox!.y).toBeGreaterThanOrEqual(0);
  expect(popupBox!.x + popupBox!.width).toBeLessThanOrEqual(viewport!.width);
  expect(popupBox!.y + popupBox!.height).toBeLessThanOrEqual(viewport!.height);
});
