import { expect, test } from "@playwright/test";
import { createPePlusFile } from "../fixtures/sample-files-pe.js";
import { openInspectionSection } from "./inspection-navigation.js";

for (const width of [1024, 1258, 1440, 2530]) {
  test(`file panel collapses without hiding file actions at ${width}px`, async ({ page }) => {
    await page.setViewportSize({ width, height: 900 });
    await page.goto("/");
    const file = createPePlusFile();
    await page.setInputFiles("#fileInput", { name: file.name, mimeType: file.type,
      buffer: Buffer.from(file.data) });
    await openInspectionSection(page, "Section headers");
    const before = (await page.locator("#workspaceViewport").boundingBox())!;

    await page.getByRole("button", { name: "Hide file panel", exact: true }).click();

    const after = (await page.locator("#workspaceViewport").boundingBox())!;
    expect(after.width - before.width).toBeGreaterThan(240);
    expect(after.y).toBe(0);
    await expect(page.locator("#fileOpenButton")).toBeVisible();
    await expect(page.locator("#directoryOpenButton")).toBeVisible();
    await expect(page.locator("#fileHashesButton")).toBeVisible();
    await expect(page.getByRole("link", { name: "GitHub", exact: true })).toBeVisible();
    await page.locator("#fileHashesButton").click();
    await expect(page.locator("#workspaceTitle")).toHaveText("File hashes");
    await expect(page.locator("#fileNameDetail")).toHaveText(file.name);
    await openInspectionSection(page, "Section headers");
    await page.locator('.workspacePanel[aria-label="Section headers"] table').first().evaluate(table => {
      // Exercise horizontal overflow even on the widest tested viewport.
      table.style.minWidth = "4000px";
    });
    const horizontal = await page.locator("#workspaceViewport").evaluate(element => {
      element.scrollLeft = element.scrollWidth - element.clientWidth;
      return { scroll: element.scrollLeft, left: element.getBoundingClientRect().left,
        titleLeft: element.querySelector("#workspaceTitle")!.getBoundingClientRect().left };
    });
    expect(horizontal.scroll).toBeGreaterThan(0);
    expect(horizontal.titleLeft).toBeGreaterThanOrEqual(horizontal.left);
    await page.getByRole("button", { name: "Show file panel", exact: true }).focus();
    await page.keyboard.press("Enter");
    await expect(page.getByRole("button", { name: "Hide file panel", exact: true }))
      .toHaveAttribute("aria-expanded", "true");
    expect((await page.locator("#workspaceViewport").boundingBox())!.width).toBe(before.width);
  });
}

test("collapsed panel search expands and focuses the existing report search", async ({ page }) => {
  await page.goto("/");
  const file = createPePlusFile();
  await page.setInputFiles("#fileInput", { name: file.name, mimeType: file.type,
    buffer: Buffer.from(file.data) });
  await page.getByRole("button", { name: "Hide file panel", exact: true }).click();

  await page.getByRole("button", { name: "Search report", exact: true }).click();

  await expect(page.locator("#workspaceFilter")).toBeFocused();
  await expect(page.getByRole("button", { name: "Hide file panel", exact: true }))
    .toHaveAttribute("aria-expanded", "true");
});

test("a collapsed desktop panel does not hide toolbar actions after a narrow round trip", async ({ page }) => {
  await page.goto("/");
  const file = createPePlusFile();
  await page.setInputFiles("#fileInput", { name: file.name, mimeType: file.type,
    buffer: Buffer.from(file.data) });
  await page.getByRole("button", { name: "Hide file panel", exact: true }).click();

  await page.setViewportSize({ width: 390, height: 844 });

  await expect(page.locator("#filePanelToggle")).toBeHidden();
  await expect(page.getByRole("button", { name: "Open files", exact: true })).toBeVisible();
  await expect(page.locator("#fileNameDetail")).toBeVisible();
  await page.setViewportSize({ width: 1258, height: 900 });
  await expect(page.getByRole("button", { name: "Show file panel", exact: true })).toBeVisible();
  await expect(page.locator("#fileOpenButton")).toBeVisible();
});

test("long navigation descriptions remain fully readable", async ({ page }) => {
  await page.setViewportSize({ width: 1024, height: 900 });
  await page.goto("/");
  const file = createPePlusFile();
  await page.setInputFiles("#fileInput", { name: file.name, mimeType: file.type,
    buffer: Buffer.from(file.data) });
  const description = page.locator(".workspaceNavItem__detail").first();
  await description.evaluate(element => {
    element.textContent = "delay imports: 9999 DLL / 999999 functions";
  });

  const visibleEnd = await description.evaluate(element => {
    const range = element.ownerDocument.createRange();
    range.setStart(element.firstChild!, element.textContent!.length - 1);
    range.setEnd(element.firstChild!, element.textContent!.length);
    return range.getBoundingClientRect().right <= element.getBoundingClientRect().right;
  });

  expect(visibleEnd).toBe(true);
});
