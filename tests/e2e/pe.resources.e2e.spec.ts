"use strict";

import { expect, test } from "@playwright/test";
import type { Page } from "@playwright/test";
import { createPeResourcePreviewFile } from "../fixtures/pe-resource-preview-file.js";
import type { MockFile } from "../helpers/mock-file.js";

const toUpload = (file: MockFile) => ({
  name: file.name,
  mimeType: file.type,
  buffer: Buffer.from(file.data)
});

const expectBaseDetails = async (page: Page, fileName: string, expectedKind: string): Promise<void> => {
  await expect(page.locator("#fileInfoCard")).toBeVisible();
  await expect(page.locator("#fileNameDetail")).toHaveText(fileName);
  await expect(page.locator("#fileBinaryTypeDetail")).toHaveText(expectedKind);
};

const openTopLevelSection = async (page: Page, title: string) => {
  const details = page.locator("#peDetailsValue > section > details").filter({
    has: page.locator("summary", { hasText: new RegExp(`^${title}\\b`) })
  }).first();
  await details.locator(":scope > summary").click();
  return details;
};

const openResourceGroup = async (page: Page, typeName: string) => {
  const details = page.locator("#peDetailsValue details details").filter({
    has: page.locator("summary", { hasText: new RegExp(`^${typeName}\\b`) })
  }).first();
  await details.locator(":scope > summary").click();
  return details;
};

test.describe("PE resource previews", () => {
  test.beforeEach(async ({ page }) => {
    await page.goto("/");
    await expect(page.getByRole("heading", { name: "Local File Inspector" })).toBeVisible();
  });

  void test("renders a broad set of PE resource previews end-to-end", async ({ page }) => {
    const file = createPeResourcePreviewFile();
    await page.setInputFiles("#fileInput", toUpload(file));

    await expectBaseDetails(page, file.name, "PE32+ executable for x86-64 (AMD64)");
    await expect(page.locator("#peDetailsValue")).toContainText("Resources");
    const resourcesSection = await openTopLevelSection(page, "Resources");
    await expect(resourcesSection).toHaveJSProperty("open", true);
    await expect(page.locator('#peDetailsValue img[alt="resource preview"]')).toHaveCount(5);

    const groupCursor = await openResourceGroup(page, "GROUP_CURSOR");
    await expect(groupCursor).toContainText("Hotspot");
    await expect(groupCursor).toContainText("7, 9");

    const groupIcon = await openResourceGroup(page, "GROUP_ICON");
    await expect(groupIcon).toContainText("ID 1");

    const bitmap = await openResourceGroup(page, "BITMAP");
    await expect(bitmap).toContainText("ID 1");

    const dialog = await openResourceGroup(page, "DIALOG");
    await expect(dialog).toContainText("Preview Dialog");
    await expect(dialog).toContainText("BUTTON");

    const menu = await openResourceGroup(page, "MENU");
    await expect(menu).toContainText("File");
    await expect(menu).toContainText("Open");

    const accelerator = await openResourceGroup(page, "ACCELERATOR");
    await expect(accelerator).toContainText("Ctrl+O");

    const fontDir = await openResourceGroup(page, "FONTDIR");
    expect(await fontDir.innerHTML()).toContain("Font-directory resource table.");

    const font = await openResourceGroup(page, "FONT");
    expect(await font.innerHTML()).toContain("TrueType font (heuristic)");

    const version = await openResourceGroup(page, "VERSION");
    await expect(version).toContainText("CompanyName");
    await expect(version).toContainText("Binary101");

    const rcdata = await openResourceGroup(page, "RCDATA");
    await expect(rcdata).toContainText("JSON/Text (heuristic)");
    await expect(rcdata).toContainText("{\"kind\":\"rcdata\"}");

    const dlgInclude = await openResourceGroup(page, "DLGINCLUDE");
    await expect(dlgInclude).toContainText("preview-dialog.h");

    const plugPlay = await openResourceGroup(page, "PLUGPLAY");
    expect(await plugPlay.innerHTML()).toContain("Legacy Plug and Play resource.");

    const vxd = await openResourceGroup(page, "VXD");
    expect(await vxd.innerHTML()).toContain("Legacy virtual-device resource.");

    const ani = await openResourceGroup(page, "ANICURSOR");
    expect(await ani.innerHTML()).toContain("Animated cursor (ANI)");

    const aniIcon = await openResourceGroup(page, "ANIICON");
    expect(await aniIcon.innerHTML()).toContain("Animated icon (ANI)");

    const html = await openResourceGroup(page, "HTML");
    expect(await html.innerHTML()).toContain("HTML is not executed");

    const manifest = await openResourceGroup(page, "MANIFEST");
    await expect(manifest).toContainText('<?xml version="1.0" encoding="UTF-8"?>');
    await expect(manifest).toContainText("Manifest cross-check");
    await expect(manifest).toContainText("Consistent");
    await expect(manifest).toContainText("Parsed tree");
    await expect(manifest).toContainText("Windows 10 / 11");
    await expect(manifest).toContainText("MANIFEST");
    await expect(manifest.getByRole("button", { name: "Copy manifest XML" })).toBeVisible();

    const messageTable = await openResourceGroup(page, "MESSAGETABLE");
    await expect(messageTable).toContainText("OK");
    await expect(messageTable).toContainText("Hi");
  });

  void test("manifest tree controls enable only the action that can still change the XML tree", async ({ page }) => {
    const file = createPeResourcePreviewFile();
    await page.setInputFiles("#fileInput", toUpload(file));

    await openTopLevelSection(page, "Resources");
    const manifest = await openResourceGroup(page, "MANIFEST");
    const viewer = manifest.locator("[data-manifest-tree-viewer]");
    const treeDetails = viewer.locator("[data-manifest-tree] details");
    const expandButton = viewer.getByRole("button", { name: "Expand all" });
    const collapseButton = viewer.getByRole("button", { name: "Collapse all" });

    expect(await treeDetails.count()).toBeGreaterThan(1);
    const initialState = await treeDetails.evaluateAll(nodes => ({
      hasCollapsed: nodes.some(node => !(node as HTMLDetailsElement).open),
      hasExpanded: nodes.some(node => (node as HTMLDetailsElement).open)
    }));
    if (initialState.hasCollapsed) {
      await expect(expandButton).toBeEnabled();
    } else {
      await expect(expandButton).toBeDisabled();
    }
    if (initialState.hasExpanded) {
      await expect(collapseButton).toBeEnabled();
    } else {
      await expect(collapseButton).toBeDisabled();
    }

    await expandButton.click();
    await expect.poll(async () => await treeDetails.evaluateAll(
      nodes => nodes.every(node => (node as HTMLDetailsElement).open)
    )).toBe(true);
    await expect(expandButton).toBeDisabled();
    await expect(collapseButton).toBeEnabled();

    await collapseButton.click();
    await expect.poll(async () => await treeDetails.evaluateAll(
      nodes => nodes.every(node => !(node as HTMLDetailsElement).open)
    )).toBe(true);
    await expect(expandButton).toBeEnabled();
    await expect(collapseButton).toBeDisabled();

    await treeDetails.nth(0).locator(":scope > summary").click();
    await expect(expandButton).toBeEnabled();
    await expect(collapseButton).toBeEnabled();
  });

  void test("manifest preview copy button copies the full XML text", async ({ page }) => {
    await page.evaluate(() => {
      const writes: string[] = [];
      Object.defineProperty(globalThis, "__manifestClipboardWrites", {
        configurable: true,
        value: writes
      });
      Object.defineProperty(navigator, "clipboard", {
        configurable: true,
        value: {
          writeText: async (text: string) => {
            writes.push(text);
          }
        }
      });
    });
    const file = createPeResourcePreviewFile();
    await page.setInputFiles("#fileInput", toUpload(file));

    await openTopLevelSection(page, "Resources");
    const manifest = await openResourceGroup(page, "MANIFEST");
    const copyButton = manifest.getByRole("button", { name: "Copy manifest XML" });
    await copyButton.click();

    await expect(page.locator("#statusMessage")).toHaveText("Manifest XML copied.");
    const clipboardWrites = await page.evaluate(
      () => (globalThis as { __manifestClipboardWrites?: string[] }).__manifestClipboardWrites || []
    );
    expect(clipboardWrites).toHaveLength(1);
    expect(clipboardWrites[0]).toContain("requestedExecutionLevel");
    expect(clipboardWrites[0]).toContain("supportedOS");
  });
});
