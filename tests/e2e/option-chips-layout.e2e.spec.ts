import { expect, test } from "@playwright/test";
import { renderLoadConfigGuardFlags } from "../../renderers/pe/load-config-widgets.js";
import { createPeLoadConfigResult } from "../../analyzers/pe/load-config/result.js";
import { createPePlusFile } from "../fixtures/sample-files-pe.js";
import { openInspectionSection } from "./inspection-navigation.js";

for (const width of [390, 1280, 2530]) {
  test(`GuardFlags use the common chip layout at ${width}px`, async ({ page }) => {
    const config = createPeLoadConfigResult();
    // IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_MASK: high nibble 1 means one extra byte.
    // https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#load-config-flags
    config.GuardFlags = 0x10017500;
    const file = createPePlusFile();
    await page.setViewportSize({ width, height: 1000 });
    await page.goto("/");
    await page.setInputFiles("#fileInput", { name: file.name, mimeType: file.type,
      buffer: Buffer.from(file.data) });
    await openInspectionSection(page, "PE/COFF headers");
    const headerWidth = await page.locator('[data-pe-lazy-section="pe-headers"] .optionsRow')
      .first().evaluate(element => element.getBoundingClientRect().width);
    await page.locator("#workspaceViewport").evaluate((viewport, html) => {
      const sample = viewport.ownerDocument.createElement("section");
      sample.id = "guardFlagLayout";
      sample.innerHTML = `<dl><dt>GuardFlags</dt><dd>${html}</dd></dl>`;
      viewport.replaceChildren(sample);
    }, renderLoadConfigGuardFlags(config));
    const rows = page.locator("#guardFlagLayout .optionsRow");
    await expect(rows).toHaveCount(1);
    const geometry = await rows.evaluate(row => {
      const chips = Array.from(row.querySelectorAll<HTMLElement>(".opt"));
      return { width: row.getBoundingClientRect().width,
        maxWidth: Number.parseFloat(row.ownerDocument.defaultView!
          .getComputedStyle(row).maxInlineSize),
        previous: chips.at(-2)!.getBoundingClientRect().y,
        stride: chips.at(-1)!.getBoundingClientRect().y,
        maxChipWidth: Math.max(...chips.map(chip => chip.getBoundingClientRect().width)) };
    });
    expect(geometry.width).toBeLessThanOrEqual(geometry.maxWidth);
    expect(geometry.maxChipWidth).toBeLessThan(geometry.width);
    if (width === 2530) {
      expect(geometry.width).toBeCloseTo(headerWidth, 0);
      expect(geometry.stride).toBe(geometry.previous);
    }
    expect(await page.locator("html").evaluate(element => element.scrollWidth))
      .toBeLessThanOrEqual(width);
  });
}
