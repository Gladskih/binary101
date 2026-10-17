import { expect, test } from "@playwright/test";
import { createPagedPeExportsFile } from "../fixtures/pe-export-table-file.js";
import { createElfMetadataFile } from "../fixtures/elf-metadata-file.js";
import { createPeImportNamesFile } from "../fixtures/pe-import-names-file.js";
import { createPeCoffLanguageFile } from "../fixtures/coff-language-symbol.js";

test("mixed PE exports load local Rust/D WASM once and survive lazy remount", async ({ page }) => {
  const assets: string[] = [];
  page.on("request", request => {
    if (/llvm-(rust|dlang)-demangle.*\.wasm$/.test(request.url())) assets.push(request.url());
  });
  await page.goto("/");
  expect(assets).toHaveLength(0);
  await page.setInputFiles("#fileInput", { name: "languages.dll",
    mimeType: "application/octet-stream", buffer: Buffer.from(createPagedPeExportsFile([
      "_RNvC1a4main", "_D3foo3barf"
    ])) });
  const section = page.locator('[data-pe-lazy-section="exports"] > details');
  await section.locator(":scope > summary").click();
  await section.getByRole("button", { name: "Next", exact: true }).click();
  await expect(section).toContainText("a::main");
  await expect(section).toContainText("float foo.bar");
  await expect(section).toContainText("_RNvC1a4main");
  await expect(section).toContainText("_D3foo3barf");
  await section.locator(":scope > summary").click();
  await section.locator(":scope > summary").click();
  await expect(section).toContainText("a::main");
  expect(assets).toHaveLength(2);
  expect(assets.every(asset => new URL(asset).origin === new URL(page.url()).origin)).toBe(true);
});

test("ELF imports/exports display both languages and preserve linker spellings", async ({ page }) => {
  const fixture = createElfMetadataFile(undefined, "_RNvC1a4main", "_D3foo3barf");
  await page.goto("/");
  await page.setInputFiles("#fileInput", { name: "languages.so",
    mimeType: "application/octet-stream", buffer: Buffer.from(fixture.file.data) });
  const section = page.locator("details").filter({
    has: page.locator(":scope > summary", { hasText: "Imports / exports" })
  });
  await section.locator("summary").first().click();
  await section.getByText("Imported symbols (1)", { exact: true }).click();
  await section.getByText("Exported symbols (1)", { exact: true }).click();
  await expect(section).toContainText("a::main");
  await expect(section).toContainText("float foo.bar");
  await expect(section).toContainText("_RNvC1a4main");
  await expect(section).toContainText("_D3foo3barf");
});

for (const [kind, name, text, label] of [["rust", "_RNvC1a4main", "a::main", "Rust v0"],
  ["dlang", "_D3foo3barf", "float foo.bar", "D"]] as const) {
  test(`${kind} loader failure preserves raw exports and the next file recovers`, async ({ page }) => {
    await page.route(`**/*llvm-${kind}-demangle*.wasm`, route => route.abort());
    await page.goto("/");
    const file = { name: "languages.dll", mimeType: "application/octet-stream",
      buffer: Buffer.from(createPagedPeExportsFile([name, "ordinary"])) };
    await page.setInputFiles("#fileInput", file);
    const section = page.locator('[data-pe-lazy-section="exports"] > details');
    await section.locator(":scope > summary").click();
    await expect(section).toContainText(`Export name demangling unavailable: ${label}:`);
    await section.getByRole("button", { name: "Next", exact: true }).click();
    await expect(section).toContainText(name);
    await expect(section).not.toContainText(text);
    await page.unroute(`**/*llvm-${kind}-demangle*.wasm`);
    await page.setInputFiles("#fileInput", file);
    await section.locator(":scope > summary").click();
    await section.getByRole("button", { name: "Next", exact: true }).click();
    await expect(section).toContainText(text);
  });

  test(`${kind} imports and COFF symbols render decoded names`, async ({ page }) => {
    await page.goto("/");
    await page.setInputFiles("#fileInput", { name: "imports.exe",
      mimeType: "application/octet-stream", buffer: Buffer.from(createPeImportNamesFile(name)) });
    const imports = page.locator('[data-pe-lazy-section="imports"] > details');
    await imports.locator(":scope > summary").click();
    await imports.getByText("eager.dll - 251 function(s)", { exact: true }).click();
    await imports.getByRole("button", { name: "Next", exact: true }).click();
    await expect(imports).toContainText(text);
    await expect(imports).toContainText(label + " (LLVM)");
    await page.setInputFiles("#fileInput", { name: "coff.exe",
      mimeType: "application/octet-stream", buffer: Buffer.from(createPeCoffLanguageFile(name)) });
    await expect(page.locator("body")).toContainText("COFF");
    const coff = page.locator("details").filter({
      has: page.locator(":scope > summary", { hasText: "Legacy COFF tail" })
    }).first();
    await coff.locator(":scope > summary").click();
    await expect(coff).toContainText(text);
    await expect(coff).toContainText(name);
  });
}
