import { expect, test } from "@playwright/test";
import { createStreamPdf } from "../fixtures/pdf-modern.js";
import { createPdfWithEmbeddedFile } from "../fixtures/pdf-document-structure.js";
import { openInspectionContent, openInspectionSection } from "./inspection-navigation.js";

test("shows decoded PDF cross-reference counts and compressed document information", async ({ page }) => {
  const sample = createStreamPdf("flate-png");
  await page.goto("/");
  await page.setInputFiles("#fileInput", {
    name: sample.name, mimeType: "application/pdf", buffer: Buffer.from(await sample.arrayBuffer())
  });
  await openInspectionContent(page, "Cross-reference");

  const result = page.locator("#analysisValue");
  const stream = result.getByRole("row").filter({ hasText: "Stream (6 0 R)" });
  await expect(stream.getByRole("cell").nth(3)).toHaveText("4");
  await openInspectionContent(page, "Proof of (nested) strings");
  await expect(result.getByText("Proof of (nested) strings", { exact: true })).toBeVisible();
  await openInspectionContent(page, "Declared page count");
  await expect(result.getByText("Declared page count", { exact: true })).toBeVisible();
  await expect(result.getByRole("heading", { name: "Warnings" })).toHaveCount(0);
});

test("shows the PDF dictionaries, page tree and embedded file as navigable sections", async ({ page }) => {
  const sample = createPdfWithEmbeddedFile();
  await page.goto("/");
  await page.setInputFiles("#fileInput", {
    name: sample.name, mimeType: sample.type, buffer: Buffer.from(await sample.arrayBuffer())
  });
  await openInspectionSection(page, "Trailer");
  await expect(page.getByRole("row").filter({ hasText: "/Size" })).toContainText("highest object number");
  await expect(page.getByText("Raw dictionary", { exact: true })).toBeVisible();
  await openInspectionSection(page, "Catalog");
  await expect(page.getByRole("row").filter({ hasText: "/PageMode" })).toContainText("/UseNone");
  await expect(page.getByText("Raw catalog", { exact: true })).toBeVisible();
  await openInspectionSection(page, "Pages");
  await expect(page.getByRole("row").filter({ hasText: "3 0 R" })).toContainText("612 × 792");
  await expect(page.getByRole("row").filter({ hasText: "5 0 R" })).toContainText("380 × 760");
  await openInspectionSection(page, "Embedded files");
  const attachment = page.getByRole("row").filter({ hasText: "notes.txt" });
  await expect(attachment).toContainText("text/plain");
  await expect(attachment).toContainText("Read &lt;notes&gt;");
});
