import { toggleInspectionSection } from "./inspection-navigation.js";
import { expect, test } from "@playwright/test";
import { createSwf, createCws, createZws, createFlashProjectorPe, createSwfTag } from "../fixtures/swf-fixtures.js";

test("standalone SWF and PE Projector show bounded metadata and extract the exact SWF", async ({ page }) => {
  const swf = createSwf();
  await page.goto("/");
  await page.setInputFiles("#fileInput", { name: "movie.swf", mimeType: "application/octet-stream",
    buffer: Buffer.from(swf) });
  await expect(page.locator("#fileBinaryTypeDetail")).toHaveText("Flash SWF (v9, FWS)");
  await expect(page.getByText("640 × 480 pixels", { exact: true })).toBeVisible();
  await expect(page.getByText("ActionScript 3", { exact: true })).toBeVisible();
  const pe = createFlashProjectorPe(swf);
  await page.setInputFiles("#fileInput", { name: pe.name, mimeType: "application/octet-stream",
    buffer: Buffer.from(pe.data) });
  const payloadSection = page.locator("details").filter({ has: page.locator("summary", { hasText: "Appended payload" }) });
  await toggleInspectionSection(payloadSection.locator("summary"));
  await expect(payloadSection.getByText("Flash Projector SWF", { exact: true })).toBeVisible();
  await expect(payloadSection.getByText("640 × 480 pixels", { exact: true })).toBeVisible();
  const downloadPromise = page.waitForEvent("download");
  await payloadSection.locator("[data-pe-payload-download]").click();
  const download = await downloadPromise;
  expect(download.suggestedFilename()).toMatch(/\.swf$/);
  const stream = await download.createReadStream();
  expect(stream).not.toBeNull();
  const chunks: Buffer[] = [];
  for await (const chunk of stream!) chunks.push(Buffer.from(chunk as Uint8Array));
  expect(Buffer.concat(chunks)).toEqual(Buffer.from(swf));
});

test("compressed Projector body findings appear automatically while its details stay closed", async ({ page }) => {
  // Opaque DoABC payload: this test checks outer tag discovery, not ABC verification.
  const swf = createSwf([createSwfTag(82, new Uint8Array(9))]);
  const pe = createFlashProjectorPe(createCws(swf));
  await page.goto("/");
  await page.setInputFiles("#fileInput", { name: pe.name, mimeType: "application/octet-stream",
    buffer: Buffer.from(pe.data) });
  const section = page.locator("[data-pe-lazy-section='appended-payloads']");
  await expect(section.locator("summary")).toContainText("1 script tag(s)");
  await expect(section.locator("details")).not.toHaveAttribute("open");
  await toggleInspectionSection(section.locator("summary"));
  await expect(section.getByRole("table", { name: "Top-level SWF tags" })).toBeVisible();
  await expect(section.getByText("DoABC", { exact: true })).toBeVisible();
  await expect(section.locator("[data-swf-body-status]")).toHaveCount(0);
});

test("standalone ZWS is decoded automatically by the LZMA worker", async ({ page }) => {
  await page.goto("/");
  await page.setInputFiles("#fileInput", { name: "movie.swf", mimeType: "application/octet-stream",
    buffer: Buffer.from(createZws()) });
  await expect(page.locator("#fileBinaryTypeDetail")).toHaveText("Flash SWF (v13, ZWS)");
  await expect(page.getByText("640 × 480 pixels", { exact: true })).toBeVisible();
  await expect(page.getByRole("table", { name: "Top-level SWF tags" })).toBeVisible();
  await expect(page.locator("[data-swf-body-status]")).toHaveCount(0);
});

test("ZWS Projector appears only after automatic body validation", async ({ page }) => {
  const file = createFlashProjectorPe(createZws());
  await page.goto("/");
  await page.setInputFiles("#fileInput", { name: file.name, mimeType: "application/octet-stream",
    buffer: Buffer.from(file.data) });
  const section = page.locator("[data-pe-lazy-section='appended-payloads']");
  await expect(section.locator("summary")).toContainText("1 payload");
  await toggleInspectionSection(section.locator("summary"));
  await expect(section.getByText("Flash Projector SWF", { exact: true })).toBeVisible();
  await expect(section.getByText("640 × 480 pixels", { exact: true })).toBeVisible();
  await expect(section.getByRole("table", { name: "Top-level SWF tags" })).toBeVisible();
});
