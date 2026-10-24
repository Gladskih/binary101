import { expect, test } from "@playwright/test";
import { createPeWithCodeViewTypeServers } from "../fixtures/pe-codeview-type-servers.js";

test("CodeView PDB dependencies show exact identities, paths and database ages", async ({ page }) => {
  const file = createPeWithCodeViewTypeServers();
  await page.setViewportSize({ width: 390, height: 960 });
  await page.goto("/");
  await page.setInputFiles("#fileInput", { name: file.name, mimeType: file.type, buffer: Buffer.from(file.data) });
  const panel = page.locator('[data-pe-lazy-section="debug"]');
  await panel.locator(":scope > details > summary").click();
  await panel.locator("summary").filter({ hasText: /^Entry #1:/ }).click();
  const servers = panel.locator('[data-sort-state-key="pe-debug-entry-0-legacy-typeServers"]');
  await expect(servers.getByRole("cell", { name: "<types>&amp;.pdb", exact: true })).toBeVisible();
  await expect(servers.getByRole("cell", {
    name: "GUID 12345678-9abc-def0-1122-334455667788", exact: true
  })).toBeVisible();
  await expect(servers.getByRole("cell", { name: "Signature 0x87654321", exact: true })).toBeVisible();
  await expect(servers.getByRole("columnheader", { name: "Sort by PDB age", exact: true })).toHaveClass(/peNumeric/);
  await expect(panel).not.toContainText("CodeView type record:");
});
