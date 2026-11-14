import { expect, test, type Page } from "@playwright/test";
import { createPeResourcePreviewFile } from "../fixtures/pe-resource-preview-file.js";
import { createZipWithEntries } from "../fixtures/zip-fixtures.js";
import { renderTreeNode, renderTreeMeta } from "../../renderers/pe/security-tree-markup.js";
import { expandInspectionCollection, openInspectionSection } from "./inspection-navigation.js";

const inspect = async (page: Page): Promise<void> => {
  await page.goto("/");
  const file = createPeResourcePreviewFile();
  await page.setInputFiles("#fileInput", { name: file.name, mimeType: file.type,
    buffer: Buffer.from(file.data) });
  await expect(page.locator("#workspaceTitle")).toHaveText("PE/COFF headers");
};

for (const width of [1024, 2530]) {
  test(`the report receives the complete desktop height at ${width}px`, async ({ page }) => {
    await page.setViewportSize({ width, height: 900 });
    await inspect(page);
    const viewport = (await page.locator("#workspaceViewport").boundingBox())!;
    expect(viewport.y).toBe(0);
    expect(viewport.height).toBe(900);
    await expect(page.locator("#fileChromeDock #fileNameDetail")).toBeVisible();
    await expect(page.locator("#fileChromeDock #fileOpenButton")).toBeVisible();
    await expect(page.locator("#fileChromeDock #workspaceFilter")).toBeVisible();
  });
}

test("ordinary metadata, table values and option labels use the base font size", async ({ page }) => {
  await page.setViewportSize({ width: 1440, height: 900 });
  await inspect(page);
  const sizes = await page.locator("#fileProperties dt, #fileSourceDetail .opt, #workspaceFilter, " +
    "#fileOpenButton, #analysisValue td").evaluateAll(elements =>
    elements.map(element => Number.parseFloat(element.ownerDocument.defaultView!
      .getComputedStyle(element).fontSize)));
  expect(sizes.length).toBeGreaterThan(5);
  expect(Math.min(...sizes)).toBeGreaterThanOrEqual(14);
  await openInspectionSection(page, "Resources");
  await expect(page.locator(".peDialog__tools label").first()).toBeVisible();
  const tools = await page.locator(".peDialog__tools label").evaluateAll(elements =>
    elements.map(element => Number.parseFloat(element.ownerDocument.defaultView!
      .getComputedStyle(element).fontSize)));
  expect(tools.length).toBeGreaterThan(0);
  expect(Math.min(...tools)).toBeGreaterThanOrEqual(14);
});

test("short desktop reports also receive the full viewport height", async ({ page }) => {
  await page.setViewportSize({ width: 1440, height: 900 });
  await page.goto("/");
  const file = createZipWithEntries();
  await page.setInputFiles("#fileInput", { name: file.name, mimeType: file.type,
    buffer: Buffer.from(file.data) });
  await expect(page.locator(".workspaceContinuous")).toBeVisible();

  const viewport = (await page.locator("#workspaceViewport").boundingBox())!;
  expect(viewport.y).toBe(0);
  expect(viewport.height).toBe(900);
});

test("hash computation keeps row and panel height stable at the base font size", async ({ page }) => {
  await page.goto("/");
  await page.setInputFiles("#fileInput", { name: "hash.bin", mimeType: "application/octet-stream",
    buffer: Buffer.alloc(128 * 1024, 37) });
  await expect(page.locator("#fileAnalysisDurationDetail")).not.toHaveText("");
  await openInspectionSection(page, "File hashes");
  const row = page.locator(".hashRow").filter({ has: page.locator("#md5Value") });
  const before = (await row.boundingBox())!.height;
  const panelBefore = (await page.locator("#hashDetails").boundingBox())!.height;
  await page.locator("#md5ComputeButton").click();
  await expect(page.locator("#md5Value")).toHaveText(/^[a-f0-9]{32}$/);
  expect((await row.boundingBox())!.height).toBeCloseTo(before, 0);
  expect((await page.locator("#hashDetails").boundingBox())!.height).toBeCloseTo(panelBefore, 0);
});

test("mobile section changes restore page scrolling even with horizontal table scrolling", async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto("/");
  const file = createZipWithEntries(Array.from({ length: 50 }, (_, index) => ({
    name: `entry-${index}`, method: 0, data: new Uint8Array([index])
  })));
  await page.setInputFiles("#fileInput", { name: file.name, mimeType: file.type,
    buffer: Buffer.from(file.data) });
  await openInspectionSection(page, "Central directory entries");
  await page.locator("html").evaluate(element => element.ownerDocument.defaultView!
    .scrollTo({ top: 500, behavior: "instant" }));
  await page.locator("#fileHashesButton").evaluate(element => element.focus({ preventScroll: true }));
  await page.keyboard.press("Enter");
  await expect(page.locator("#workspaceTitle")).toHaveText("File hashes");
  await page.locator("#workspaceNavigation button").filter({
    has: page.getByText("Central directory entries", { exact: true })
  }).evaluate(element => element.focus({ preventScroll: true }));
  await page.keyboard.press("Enter");
  await expect.poll(() => page.locator("html").evaluate(element => element.ownerDocument.defaultView!
    .scrollY)).toBe(500);
});

for (const width of [768, 2530]) {
  test(`nested resource tables stay inside the enclosing cell at ${width}px`, async ({ page }) => {
    await page.setViewportSize({ width, height: 900 });
    await inspect(page);
    await openInspectionSection(page, "Resources");
    const version = page.locator("[data-pe-resource-group]").filter({
      has: page.locator(".collectionSummary", { hasText: /^VERSION\b/ })
    });
    await expandInspectionCollection(version);
    const bounds = await version.locator("table table:visible").evaluateAll(tables => tables.map(table => ({
      right: table.getBoundingClientRect().right,
      cellRight: table.parentElement!.closest("td")!.getBoundingClientRect().right
    })));
    expect(bounds.length).toBeGreaterThan(0);
    expect(bounds.every(pair => pair.right <= pair.cellRight)).toBe(true);
  });
}

test("certificate nodes keep a readable width regardless of whether they have children", async ({ page }) => {
  await page.setViewportSize({ width: 2530, height: 1100 });
  await inspect(page);
  const meta = [renderTreeMeta("Issuer", "CN=Example Certificate Authority, O=Example, C=US")];
  const leaf = renderTreeNode("Trust anchor: Example Root", [], meta);
  const parent = renderTreeNode("Certificate: Example Intermediate", [], meta, leaf);
  await page.locator("#analysisValue").evaluate((element, tree) => {
    element.insertAdjacentHTML("beforeend", `<section><h4>Certificate fixture</h4>` +
      `<div class="peSecurityCertList"><section class="peSecurityCertCard">` +
      `<ul class="peSecurityTree">${tree}</ul></section></div></section>`);
  }, parent);
  await openInspectionSection(page, "Certificate fixture");
  const widths = await page.locator(".peSecurityTreeNode").evaluateAll(nodes =>
    nodes.map(node => node.getBoundingClientRect().width));
  expect(widths).toHaveLength(2);
  expect(Math.max(...widths)).toBeLessThan(900);
  expect((await page.locator(".peSecurityCertCard").boundingBox())!.width).toBeLessThan(900);
});

test("closing metadata keeps the file action rail available without a second top toolbar", async ({ page }) => {
  await page.setViewportSize({ width: 2530, height: 1100 });
  await inspect(page);
  const before = (await page.locator(".workspaceContent").boundingBox())!.width;
  await page.locator("#fileDetails > summary").click();
  const after = (await page.locator(".workspaceContent").boundingBox())!.width;
  expect(after).toBeCloseTo(before, 0);
  await expect(page.locator("#fileOpenButton")).toBeVisible();
  await expect(page.locator(".appHeader")).toBeHidden();
  await page.locator("#fileDetails > summary").click();
  expect((await page.locator(".workspaceContent").boundingBox())!.width).toBeCloseTo(before, 0);
});
