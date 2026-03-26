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
  await expect(page.locator("#fileOriginalName")).toHaveText(fileName);
  await expect(page.locator("#fileKindDisplay")).toHaveText(expectedKind);
  await expect(page.locator("#fileBinaryTypeDetail")).toHaveText(expectedKind);
};

const openResourceGroup = async (page: Page, typeName: string) => {
  const details = page.locator("#peDetailsValue details").filter({ hasText: typeName }).first();
  await details.locator("summary").click();
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
    await expect(page.locator("#peDetailsTerm")).toHaveText("PE/COFF details");
    await expect(page.locator("#peDetailsValue")).toContainText("Resources");
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

    const version = await openResourceGroup(page, "VERSION");
    await expect(version).toContainText("CompanyName");
    await expect(version).toContainText("Binary101");

    const rcdata = await openResourceGroup(page, "RCDATA");
    await expect(rcdata).toContainText("JSON/Text (heuristic)");
    await expect(rcdata).toContainText("{\"kind\":\"rcdata\"}");

    const ani = await openResourceGroup(page, "ANICURSOR");
    await expect(ani).toContainText("Animated cursor/icon (ANI, heuristic)");

    const messageTable = await openResourceGroup(page, "MESSAGETABLE");
    await expect(messageTable).toContainText("OK");
    await expect(messageTable).toContainText("Hi");
  });
});
