"use strict";

import { expect, test } from "@playwright/test";
import type { Page } from "@playwright/test";
import { createGzipFile } from "../fixtures/gzip-fixtures.js";
import { createPngFile } from "../fixtures/image-sample-files.js";
import { createPeResourcePreviewFile } from "../fixtures/pe-resource-preview-file.js";
import type { MockFile } from "../helpers/mock-file.js";
import { NARROW_LAYOUT_VIEWPORT } from "./viewports.js";

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
  await page.setViewportSize(NARROW_LAYOUT_VIEWPORT);
  await inspectFile(page, createPngFile());

  await expect(page.locator("#fileIconWrap")).toBeHidden();
  await expectFullWidthDetails(page);

  await page.setViewportSize({ width: 1280, height: 720 });
  await inspectFile(page, createPngFile());

  await expect(page.locator("#fileIconWrap")).toBeHidden();
  await expectFullWidthDetails(page);
});

void test("places a PE icon below the summary on phone-sized screens", async ({ page }) => {
  await page.setViewportSize(NARROW_LAYOUT_VIEWPORT);
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
  await page.setViewportSize(NARROW_LAYOUT_VIEWPORT);
  await inspectFile(page, createPeResourcePreviewFile());

  const cardBox = await page.locator("#fileInfoCard").boundingBox();
  const hashesBox = await page.locator("#hashDetails").boundingBox();
  const sectionBox = await page.locator("#analysisValue > .peSection").first().boundingBox();
  expect(cardBox).not.toBeNull();
  expect(hashesBox).not.toBeNull();
  expect(sectionBox).not.toBeNull();
  expect(cardBox!.x).toBeCloseTo(0, 0);
  expect(hashesBox!.x).toBeCloseTo(0, 0);
  expect(sectionBox!.x).toBeCloseTo(0, 0);
});

void test("insets unsectioned analysis content on phone-sized screens", async ({ page }) => {
  await page.setViewportSize(NARROW_LAYOUT_VIEWPORT);
  await inspectFile(page, createGzipFile({ payload: Buffer.from("hello") }));

  const details = page.locator("#analysisValue");
  const headingBox = await details.locator(":scope > h3").boundingBox();
  expect(await details.locator(":scope > section").count()).toBe(0);
  expect(headingBox).not.toBeNull();
  expect(headingBox!.x).toBeCloseTo(16, 0);
});

void test("shows a hover affordance for collapsible PE sections", async ({ page }) => {
  await page.setViewportSize({ width: 1280, height: 720 });
  await inspectFile(page, createPeResourcePreviewFile());

  const sectionSummary = page.locator(".peSectionSummary").first();
  const initialBorderColor = await sectionSummary.evaluate(element =>
    element.ownerDocument.defaultView!.getComputedStyle(element).borderColor
  );
  await sectionSummary.hover();
  const hoverBorderColor = await sectionSummary.evaluate(element =>
    element.ownerDocument.defaultView!.getComputedStyle(element).borderColor
  );

  expect(
    await sectionSummary.evaluate(element =>
      element.ownerDocument.defaultView!.getComputedStyle(element).cursor
    )
  ).toBe("pointer");
  expect(hoverBorderColor).not.toBe(initialBorderColor);
});
