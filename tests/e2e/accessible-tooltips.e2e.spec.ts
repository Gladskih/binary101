"use strict";

import { expect, test } from "@playwright/test";
import { createPePlusDirectIatReferenceFile } from "../fixtures/pe-direct-iat-reference-file.js";
import { createPePlusFile } from "../fixtures/sample-files-pe.js";
import { NARROW_LAYOUT_VIEWPORT } from "./viewports.js";

void test("keeps a file-summary tooltip within a phone viewport", async ({ page }) => {
  await page.setViewportSize(NARROW_LAYOUT_VIEWPORT);
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

void test("keeps an import-table tooltip visible above surrounding content", async ({ page }) => {
  await page.setViewportSize(NARROW_LAYOUT_VIEWPORT);
  await page.goto("/");
  const file = createPePlusDirectIatReferenceFile();
  await page.setInputFiles("#fileInput", {
    name: file.name,
    mimeType: file.type,
    buffer: Buffer.from(file.data)
  });
  await page.locator("#peImportsPanel > details > summary").click();
  await page.locator("#peImportsPanel details details > summary").first().click();
  const button = page.getByRole("button", { name: /JMP instructions/ });
  await button.click();
  const popup = button.locator("~ .accessibleTooltipPopup");
  await expect(popup).toBeVisible();
  const isFullyHitTestable = await popup.evaluate(element => {
    const bounds = element.getBoundingClientRect();
    const inset = 2;
    return [
      { x: bounds.left + inset, y: bounds.top + bounds.height / 2 },
      { x: bounds.right - inset, y: bounds.top + bounds.height / 2 },
      { x: bounds.left + bounds.width / 2, y: bounds.top + inset },
      { x: bounds.left + bounds.width / 2, y: bounds.bottom - inset }
    ].every(point => globalThis.document.elementFromPoint(point.x, point.y) === element);
  });
  expect(isFullyHitTestable).toBe(true);
});
