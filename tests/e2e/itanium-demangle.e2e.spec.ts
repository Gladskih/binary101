import { expect, test } from "@playwright/test";
import { createPagedPeExportsFile } from "../fixtures/pe-export-table-file.js";
import { createElfItaniumFile } from "../fixtures/elf-itanium-file.js";

test("PE Itanium exports use same-origin WASM and survive lazy remount", async ({ page }) => {
  const assets: string[] = [];
  page.on("request", request => {
    if (/llvm-itanium-demangle.*\.wasm$/.test(request.url())) assets.push(request.url());
  });
  await page.goto("/");
  await page.setInputFiles("#fileInput", { name: "itanium.dll",
    mimeType: "application/octet-stream", buffer: Buffer.from(createPagedPeExportsFile([
      "_Z1fi", "_ZTVN4demo6WidgetE"
    ])) });
  const section = page.locator('[data-pe-lazy-section="exports"] > details');
  await section.locator(":scope > summary").click();
  await section.getByRole("button", { name: "Next", exact: true }).click();
  await expect(section).toContainText("f(int)");
  await expect(section).toContainText("_Z1fi");
  await expect(section).toContainText("vtable for demo::Widget");
  await section.locator(":scope > summary").click();
  await section.locator(":scope > summary").click();
  await expect(section).toContainText("f(int)");
  expect(assets).toHaveLength(1);
  expect(new URL(assets[0]!).origin).toBe(new URL(page.url()).origin);
});

test("ELF dynamic symbols show decoded and linker names", async ({ page }) => {
  await page.goto("/");
  await page.setInputFiles("#fileInput", { name: "itanium.elf",
    mimeType: "application/octet-stream", buffer: Buffer.from(createElfItaniumFile()) });
  const section = page.locator("details").filter({
    has: page.locator(":scope > summary", { hasText: "Imports / exports" })
  });
  await section.locator("summary").first().click();
  await section.getByText("Exported symbols (1)", { exact: true }).click();
  await expect(section).toContainText("f(int)");
  await expect(section).toContainText("_Z1fi");
});

test("a failed Itanium loader preserves PE names and the next file recovers", async ({ page }) => {
  await page.route("**/*llvm-itanium-demangle*.wasm", route => route.abort());
  await page.goto("/");
  const file = { name: "itanium.dll", mimeType: "application/octet-stream",
    buffer: Buffer.from(createPagedPeExportsFile(["_Z1fi", "_ZTVN4demo6WidgetE"])) };
  await page.setInputFiles("#fileInput", file);
  const section = page.locator('[data-pe-lazy-section="exports"] > details');
  await section.locator(":scope > summary").click();
  await expect(section).toContainText("Export name demangling unavailable:");
  await section.getByRole("button", { name: "Next", exact: true }).click();
  await expect(section).toContainText("_Z1fi");
  await expect(section).not.toContainText("f(int)");
  await page.unroute("**/*llvm-itanium-demangle*.wasm");
  await page.setInputFiles("#fileInput", file);
  await section.locator(":scope > summary").click();
  await section.getByRole("button", { name: "Next", exact: true }).click();
  await expect(section).toContainText("f(int)");
});
