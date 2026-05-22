"use strict";

import { expect, test } from "@playwright/test";
import { readFile } from "node:fs/promises";
import { renderPeDiagnostics } from "../../renderers/pe/diagnostics.js";

void test("PE diagnostic warning bullets stay inside the panel and wrapped text column", async ({
  page
}) => {
  const css = await readFile("style.css", "utf8");
  await page.setViewportSize({ width: 520, height: 260 });
  await page.setContent(
    `<style>${css}</style><main id="resultsSection"><dl>` +
      `<dt id="peDetailsTerm">PE/COFF details</dt><dd id="peDetailsValue">` +
      `<section class="peSection"><details class="peSectionDetails" open>` +
      `<summary class="peSectionSummary"><b>Resources</b> - 8 kinds</summary>` +
      `<div class="peSectionBody">` +
      renderPeDiagnostics("Resource warnings", [
        "Resource string area and Resource Data entry area are interleaved: first resource data entry at 0x136, first late resource string at 0x146, and the string area ends at 0x414a."
      ]) +
      `</div></details></section></dd></dl></main>`
  );
  await page.locator(".peDiagnosticDetails > summary").click();

  const layout = await page.locator(".peDiagnosticItem").evaluate(item => {
    const bullet = item.querySelector("span[aria-hidden='true']");
    const text = item.querySelector(".peDiagnosticText");
    const details = item.closest(".peDiagnosticDetails");
    if (!(bullet instanceof HTMLElement) || !(text instanceof HTMLElement)) {
      throw new Error("Expected rendered bullet and diagnostic text spans.");
    }
    if (!(details instanceof HTMLElement)) {
      throw new Error("Expected diagnostic details wrapper.");
    }
    const itemRect = item.getBoundingClientRect();
    const bulletRect = bullet.getBoundingClientRect();
    const textRect = text.getBoundingClientRect();
    const detailsRect = details.getBoundingClientRect();
    const view = item.ownerDocument.defaultView;
    if (!view) throw new Error("Expected a window for layout inspection.");
    const detailsBeforeStyle = view.getComputedStyle(details, "::before");
    const lineLeft = detailsRect.left + Number.parseFloat(detailsBeforeStyle.left);
    const range = item.ownerDocument.createRange();
    range.selectNodeContents(text);
    const textLineRects = [...range.getClientRects()].map(rect => ({
      left: rect.left,
      right: rect.right
    }));
    return {
      bulletLeft: bulletRect.left,
      bulletRight: bulletRect.right,
      detailsBeforeDisplay: detailsBeforeStyle.display,
      detailsRight: detailsRect.right,
      itemLeft: itemRect.left,
      lineLeft,
      textLeft: textRect.left,
      textLineRects
    };
  });

  expect(layout.detailsBeforeDisplay).not.toBe("none");
  expect(layout.lineLeft).toBeLessThan(layout.bulletLeft);
  expect(layout.bulletLeft).toBeGreaterThanOrEqual(layout.itemLeft);
  expect(layout.bulletLeft).toBeGreaterThan(layout.lineLeft);
  expect(layout.textLeft).toBeGreaterThan(layout.bulletRight);
  expect(layout.textLineRects.length).toBeGreaterThan(1);
  for (const rect of layout.textLineRects) {
    expect(rect.left).toBeGreaterThanOrEqual(layout.textLeft - 0.5);
    expect(rect.right).toBeLessThanOrEqual(layout.detailsRight + 0.5);
  }
});
