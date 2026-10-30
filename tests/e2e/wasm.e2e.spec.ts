import { expect, test } from "@playwright/test";
import { createWasmFile, wasmModule, wasmSection, wasmString, wasmUnsigned } from "../fixtures/wasm-fixtures.js";

test("WebAssembly displays deep local analysis and executable sample results", async ({ page }) => {
  const errors: string[] = [];
  const requests: string[] = [];
  page.on("pageerror", error => errors.push(error.message));
  page.on("request", request => requests.push(request.url()));
  await page.goto("/");
  await page.setInputFiles("#fileInput", { name: "analysis-demo.wasm", mimeType: "application/wasm",
    buffer: Buffer.from(await createWasmFile().arrayBuffer()) });
  await expect(page.getByRole("heading", { name: "WebAssembly module" })).toBeVisible();
  await expect(page.getByRole("heading", { name: "Imports", exact: true })).toBeVisible();
  await expect(page.getByRole("heading", { name: "Data", exact: true })).toBeVisible();
  await page.getByText("Instructions (4)", { exact: true }).click();
  await expect(page.getByRole("cell", { name: "i32.add", exact: true })).toBeVisible();
  await expect(page.getByRole("cell", { name: "analysis-demo", exact: true })).toHaveCount(0);
  expect(errors).toEqual([]);
  expect(requests.every(url => new URL(url).origin === new URL(page.url()).origin)).toBe(true);
});

test("instruction pagination exposes every instruction without an analysis cap", async ({ page }) => {
  const body = [0, ...new Array<number>(151).fill(1), 0x0b];
  const file = wasmModule(wasmSection(1, [1, 0x60, 0, 0]), wasmSection(3, [1, 0]),
    wasmSection(10, [1, ...wasmUnsigned(body.length), ...body]));
  await page.goto("/");
  await page.setInputFiles("#fileInput", { name: "many.wasm", mimeType: "application/wasm",
    buffer: Buffer.from(await file.arrayBuffer()) });
  await page.getByText("Instructions (152)", { exact: true }).click();
  const table = page.locator('[data-paged-sortable-table-id="wasm-code-0"]');
  await expect(table.getByRole("cell", { name: "nop", exact: true })).toHaveCount(50);
  await table.getByRole("button", { name: "Last", exact: true }).click();
  await expect(table.getByRole("cell", { name: "end", exact: true })).toBeVisible();
  await expect(table.getByRole("cell", { name: "nop", exact: true })).toHaveCount(1);
});

test("malformed WebAssembly displays visible warnings", async ({ page }) => {
  await page.goto("/");
  await page.setInputFiles("#fileInput", { name: "broken.wasm", mimeType: "application/wasm",
    buffer: Buffer.from(await wasmModule([10, 100, 0]).arrayBuffer()) });
  await expect(page.getByRole("heading", { name: "Issues", exact: true })).toBeVisible();
  await expect(page.locator(".issueList")).toContainText("truncated");
});

test("function pagination enhances nested instruction tables on later pages", async ({ page }) => {
  const count = 61;
  const body = [0, ...new Array<number>(55).fill(1), 0x0b];
  const file = wasmModule(wasmSection(1, [1, 0x60, 0, 0]),
    wasmSection(3, [count, ...new Array<number>(count).fill(0)]),
    wasmSection(10, [count, ...Array.from({ length: count }, () => [body.length, ...body]).flat()]));
  await page.goto("/");
  await page.setInputFiles("#fileInput", { name: "functions.wasm", mimeType: "application/wasm",
    buffer: Buffer.from(await file.arrayBuffer()) });
  const functions = page.locator('[data-paged-sortable-table-id="wasm-functions"]');
  await functions.getByRole("button", { name: "Last", exact: true }).first().click();
  const instructions = page.locator('[data-paged-sortable-table-id="wasm-code-60"]');
  await instructions.locator("xpath=..").getByText("Instructions (56)", { exact: true }).click();
  await instructions.getByRole("button", { name: "Last", exact: true }).click();
  await expect(instructions.getByRole("cell", { name: "end", exact: true })).toBeVisible();
});

test("preserves entity-like names literally and right-aligns numeric cells", async ({ page }) => {
  const file = wasmModule(wasmSection(1, [1, 0x60, 0, 0]), wasmSection(3, [1, 0]),
    wasmSection(7, [1, ...wasmString("&lt;entry&gt;"), 0, 0]),
    wasmSection(10, [1, 2, 0, 0x0b]), wasmSection(0, [...wasmString("name"),
      ...wasmSection(0, wasmString("&lt;module&gt;"))]));
  await page.goto("/");
  await page.setInputFiles("#fileInput", { name: "names.wasm", mimeType: "application/wasm",
    buffer: Buffer.from(await file.arrayBuffer()) });
  await expect(page.getByText("&lt;module&gt;", { exact: true })).toBeVisible();
  const exports = page.locator('[data-sort-state-key="wasm-exports"]');
  await expect(exports.getByRole("cell", { name: "&lt;entry&gt;", exact: true })).toBeVisible();
  await expect(exports.getByRole("cell", { name: "0", exact: true })).toHaveCSS("text-align", "right");
});
