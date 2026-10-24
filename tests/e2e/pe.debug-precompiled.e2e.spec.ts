import { expect, test } from "@playwright/test";
import { createPeWithCodeViewPrecompiledTypes } from "../fixtures/pe-codeview-precompiled.js";

test("CodeView local members and source names survive an external precompiled import", async ({ page }) => {
  const file = createPeWithCodeViewPrecompiledTypes();
  await page.goto("/");
  await page.setInputFiles("#fileInput", { name: file.name, mimeType: file.type, buffer: Buffer.from(file.data) });
  const panel = page.locator('[data-pe-lazy-section="debug"]');
  await panel.locator(":scope > details > summary").click();
  await panel.locator("summary").filter({ hasText: /^Entry #1:/ }).click();
  const members = panel.locator('[data-sort-state-key="pe-debug-entry-0-legacy-members"]');
  await expect(members.getByRole("cell", { name: "count", exact: true })).toBeVisible();
  await expect(members.getByRole("cell", { name: "PchLocal", exact: true })).toBeVisible();
  await expect(members.getByRole("cell", { name: "int32", exact: true })).toBeVisible();
  const sources = panel.locator('[data-sort-state-key="pe-debug-entry-0-legacy-typeSources"]');
  await expect(sources.getByRole("cell", { name: "PchLocal", exact: true })).toBeVisible();
  await expect(sources.getByRole("cell", { name: "PchConsumer.cpp", exact: true })).toBeVisible();
  await expect(panel).not.toContainText("indices are unresolved");
});
