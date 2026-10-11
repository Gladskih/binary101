"use strict";

import { expect, test } from "@playwright/test";
import { createPagedPeExportsFile } from "../fixtures/pe-export-table-file.js";

test("PE exports preserve aliases across pagination, sorting and lazy remount", async ({ page }) => {
  await page.goto("/");
  await page.setInputFiles("#fileInput", {
    buffer: Buffer.from(createPagedPeExportsFile()), name: "exports.exe",
    mimeType: "application/octet-stream"
  });
  const details = page.locator('[data-pe-lazy-section="exports"] > details');
  await details.locator(":scope > summary").click();
  const table = details.locator('[data-paged-sortable-table-id="pe-exports"]');
  await expect(table.locator("tbody tr")).toHaveCount(250);
  await table.getByRole("button", { name: "Next", exact: true }).click();
  await expect(table.locator("tbody tr")).toHaveCount(1);
  await expect(table.locator("tbody td:nth-child(3)")).toHaveText("Alpha<Beta&lt;");
  await details.locator(":scope > summary").click();
  await details.locator(":scope > summary").click();
  await expect(table).toContainText("Showing 251-251 of 251");
  await table.getByRole("button", { name: "First", exact: true }).click();
  await table.getByRole("button", { name: "Sort by Ordinal", exact: true }).click();
  await table.getByRole("button", { name: "Sort by Ordinal", exact: true }).click();
  await expect(table.locator("tbody tr").first().locator("td:nth-child(2)")).toHaveText("251");
  await expect(table.locator("tbody tr").first().locator("td:nth-child(3)"))
    .toHaveText("Alpha<Beta&lt;");
});

test("MSVC export signatures survive pagination, sorting and lazy remount", async ({ page }) => {
  await page.goto("/");
  await page.setInputFiles("#fileInput", {
    buffer: Buffer.from(createPagedPeExportsFile(["??$square@H@demo@@YAHH@Z", "?f@@YAHH@Ztail"])),
    name: "cpp-exports.dll", mimeType: "application/octet-stream"
  });
  const details = page.locator('[data-pe-lazy-section="exports"] > details');
  await details.locator(":scope > summary").click();
  const table = details.locator('[data-paged-sortable-table-id="pe-exports"]');
  await table.getByRole("button", { name: "Next", exact: true }).click();
  await expect(table).toContainText("int __cdecl demo::square<int>(int)");
  await expect(table).toContainText("??$square@H@demo@@YAHH@Z");
  await expect(table).toContainText("?f@@YAHH@Ztail");
  await expect(table).not.toContainText("int __cdecl f(int)");
  await details.locator(":scope > summary").click();
  await details.locator(":scope > summary").click();
  await expect(table).toContainText("int __cdecl demo::square<int>(int)");
  await table.getByRole("button", { name: "First", exact: true }).click();
  await table.getByRole("button", { name: "Sort by Ordinal", exact: true }).click();
  await table.getByRole("button", { name: "Sort by Ordinal", exact: true }).click();
  await expect(table.locator("tbody tr").first()).toContainText("int __cdecl demo::square<int>(int)");
});

test("a failed export demangler preserves raw names and later files recover", async ({ page }) => {
  await page.route("**/*llvm-msvc-demangle*.wasm", route => route.abort());
  await page.goto("/");
  const file = { buffer: Buffer.from(createPagedPeExportsFile(["?f@@YAHH@Z", "PlainAlias"])),
    name: "cpp-exports.dll", mimeType: "application/octet-stream" };
  await page.setInputFiles("#fileInput", file);
  const details = page.locator('[data-pe-lazy-section="exports"] > details');
  await details.locator(":scope > summary").click();
  await expect(details).toContainText("Export name demangling unavailable:");
  await details.getByRole("button", { name: "Next", exact: true }).click();
  await expect(details).toContainText("?f@@YAHH@Z");
  await expect(details).toContainText("PlainAlias");
  await page.unroute("**/*llvm-msvc-demangle*.wasm");
  await page.setInputFiles("#fileInput", file);
  await details.locator(":scope > summary").click();
  await details.getByRole("button", { name: "Next", exact: true }).click();
  await expect(details).toContainText("int __cdecl f(int)");
});
