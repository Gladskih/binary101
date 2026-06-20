"use strict";

import { expect, test } from "@playwright/test";
import type { Page } from "@playwright/test";
import { createPngFile } from "../fixtures/image-sample-files.js";
import { createPeResourcePreviewFile } from "../fixtures/pe-resource-preview-file.js";
import type { MockFile } from "../helpers/mock-file.js";

const toUpload = (file: MockFile) => ({
  name: file.name,
  mimeType: file.type,
  buffer: Buffer.from(file.data)
});

const inspectFile = async (page: Page, file: MockFile): Promise<void> => {
  await page.goto("/");
  await page.setInputFiles("#fileInput", toUpload(file));
  await expect(page.locator("#fileInfoCard")).toBeVisible();
};

const expectFullWidthDetails = async (page: Page): Promise<void> => {
  const primary = page.locator(".filePrimaryInfo");
  const primaryBox = await primary.boundingBox();
  const detailsBox = await page.locator(".filePrimaryInfo > dl").boundingBox();
  const horizontalPadding = await primary.evaluate(element => {
    const style = element.ownerDocument.defaultView!.getComputedStyle(element);
    return parseFloat(style.paddingLeft) + parseFloat(style.paddingRight);
  });
  expect(primaryBox).not.toBeNull();
  expect(detailsBox).not.toBeNull();
  expect(detailsBox!.width).toBeCloseTo(primaryBox!.width - horizontalPadding, 0);
};

void test("uses full summary width without a PE icon", async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await inspectFile(page, createPngFile());

  await expect(page.locator("#fileIconWrap")).toBeHidden();
  await expectFullWidthDetails(page);

  await page.setViewportSize({ width: 1280, height: 720 });
  await inspectFile(page, createPngFile());

  await expect(page.locator("#fileIconWrap")).toBeHidden();
  await expectFullWidthDetails(page);
});

void test("places a PE icon below the summary on phone-sized screens", async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await inspectFile(page, createPeResourcePreviewFile());

  const detailsBox = await page.locator(".filePrimaryInfo > dl").boundingBox();
  const iconBox = await page.locator("#fileIcon").boundingBox();
  expect(detailsBox).not.toBeNull();
  expect(iconBox).not.toBeNull();
  expect(iconBox!.y).toBeGreaterThan(detailsBox!.y + detailsBox!.height);
});

void test("places a PE icon to the right of the summary on wide screens", async ({ page }) => {
  await page.setViewportSize({ width: 1280, height: 720 });
  await inspectFile(page, createPeResourcePreviewFile());

  const detailsBox = await page.locator(".filePrimaryInfo > dl").boundingBox();
  const iconBox = await page.locator("#fileIcon").boundingBox();
  expect(detailsBox).not.toBeNull();
  expect(iconBox).not.toBeNull();
  expect(iconBox!.x).toBeGreaterThan(detailsBox!.x + detailsBox!.width);
});

void test("uses the full phone width for the PE result card and its sections", async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await inspectFile(page, createPeResourcePreviewFile());

  const cardBox = await page.locator("#fileInfoCard").boundingBox();
  const sectionBox = await page.locator("#peDetailsValue > .peSection").first().boundingBox();
  expect(cardBox).not.toBeNull();
  expect(sectionBox).not.toBeNull();
  expect(cardBox!.x).toBeCloseTo(0, 0);
  expect(sectionBox!.x).toBeCloseTo(0, 0);
});
