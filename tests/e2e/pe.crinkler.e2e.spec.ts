import { expect, test } from "@playwright/test";
import { CRINKLER_13_PREFIX, CRINKLER_30_PREFIX, CRINKLER_30_TINY } from "../fixtures/crinkler-bytes.js";
import { openInspectionSection } from "./inspection-navigation.js";

const upload = (hex: string) => ({
  name: "crinkler-probe.exe",
  mimeType: "application/octet-stream",
  buffer: Buffer.from(hex, "hex")
});

test("Crinkler retains the PE header and mounts the decoded report", async ({ page }) => {
  await page.goto("/");
  await page.setInputFiles("#fileInput", upload(CRINKLER_30_TINY));
  await expect(page.getByText("Crinkler-packed PE", { exact: true })).toBeVisible();
  await openInspectionSection(page, "PE/COFF headers");
  await expect(page.getByText(/The declared optional header ends here/)).toBeVisible();
  await page.locator("#workspaceNavigation button")
    .filter({ hasText: "Crinkler executable packer" }).focus();
  await page.keyboard.press("Enter");
  const section = page.locator('[data-pe-lazy-section="crinkler"]');
  await expect(section.getByText("Tiny Import resolver", { exact: true })).toBeVisible();
  await expect(section.getByText("Verified unpacked bytes", { exact: true })).toBeVisible();
  await expect(section.getByRole("table")).toHaveCount(0);
});

test("Crinkler model tables scroll and retain readable columns at 200% in both themes",
  async ({ page }) => {
    await page.setViewportSize({ width: 390, height: 844 });
    await page.goto("/");
    await page.setInputFiles("#fileInput", upload(CRINKLER_30_PREFIX));
    await openInspectionSection(page, "Crinkler executable packer");
    const section = page.locator('[data-pe-lazy-section="crinkler"]');
    const table = section.getByRole("table");
    const wrapper = section.locator(".tableWrap");
    for (const colorScheme of ["light", "dark"] as const) {
      await page.emulateMedia({ colorScheme });
      await page.locator("html").evaluate(element => { element.style.zoom = "2"; });
      await expect(table.getByRole("columnheader", { name: "Unpacked bytes" })).toBeVisible();
      expect(await wrapper.evaluate(element => element.scrollWidth > element.clientWidth))
        .toBe(true);
      await wrapper.evaluate(element => { element.scrollLeft = element.scrollWidth; });
      expect(await wrapper.evaluate(element => element.scrollLeft)).toBeGreaterThan(0);
    }
  });

test("Crinkler directory fields stay visible with consistent parser warnings", async ({ page }) => {
  await page.goto("/");
  await page.setInputFiles("#fileInput", upload(CRINKLER_13_PREFIX));
  await openInspectionSection(page, "Data directories");
  const table = page.locator(".peDataDirectoryTable");
  await expect(table.getByRole("img", { name: /Unverified: RVA does not map/ })).toHaveCount(2);
  await expect(table.getByRole("img", { name: "Unverified: RVA is zero" })).toBeVisible();
  await expect(table.locator(".peDataDirectoryStatus--present")).toHaveCount(0);
  for (const theme of ["dark", "light"] as const) {
    await page.emulateMedia({ colorScheme: theme });
    await expect(table.locator(".peDataDirectoryStatus--unverified").first())
      .not.toHaveCSS("box-shadow", "none");
  }
  await expect(page.getByText("Import warnings", { exact: true })).toBeVisible();
  await expect(page.getByText("Resource warnings", { exact: true })).toBeVisible();
  await expect(page.getByText("Export warnings", { exact: true })).toBeVisible();
  await expect(page.getByText("OrdinalBase", { exact: true })).toHaveCount(0);
});
