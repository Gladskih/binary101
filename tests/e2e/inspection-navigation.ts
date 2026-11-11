import { expect, type Locator, type Page } from "@playwright/test";

export const expandInspectionCollection = async (collection: Locator): Promise<void> => {
  await expect(collection).toBeVisible();
  if (await collection.evaluate(element =>
    element.tagName === "DETAILS" && !element.hasAttribute("open"))) {
    await collection.locator(":scope > summary").click();
  }
};

export const openInspectionSection = async (page: Page, title: string): Promise<void> => {
  await expect(page.locator("#fileInfoCard")).toBeVisible();
  if (title === "File hashes") {
    await page.locator("#fileHashesButton").click();
    await expect(page.locator("#workspaceTitle")).toHaveText("File hashes");
    return;
  }
  const select = page.locator("#workspaceMobileView");
  if (await select.isVisible()) {
    await select.selectOption({ label: title });
  } else {
    await page.locator("#workspaceNavigation button").filter({
      has: page.getByText(title, { exact: true })
    }).click();
  }
  await expect(page.locator("#workspaceTitle")).toHaveText(title);
};

// Outer format disclosures became workspace navigation. Nested disclosures remain controls.
export const toggleInspectionSection = async (summary: Locator): Promise<void> => {
  const title = await summary.evaluate(element => {
    const panel = element.closest(".workspacePanel");
    const details = element.parentElement;
    return panel && (details === panel || details?.parentElement === panel)
      ? panel.getAttribute("aria-label") : null;
  });
  if (!title) { await summary.click(); return; }
  const heading = summary.page().locator("#workspaceTitle");
  await openInspectionSection(summary.page(), await heading.textContent() === title ? "File hashes" : title);
};

export const openInspectionContent = async (page: Page, text: string | RegExp): Promise<void> => {
  const panel = page.locator("#analysisValue > .workspacePanel").filter({ hasText: text }).first();
  await panel.waitFor({ state: "attached" });
  await openInspectionSection(page, (await panel.getAttribute("aria-label"))!);
};

export const openInspectionElement = async (element: Locator): Promise<void> => {
  await element.first().waitFor({ state: "attached" });
  const title = await element.first().evaluate(node =>
    node.closest(".workspacePanel")?.getAttribute("aria-label"));
  if (title) await openInspectionSection(element.page(), title);
};
