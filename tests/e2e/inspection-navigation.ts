import { expect, type Locator, type Page } from "@playwright/test";

export const computeInspectionHash = async (page: Page, id: string): Promise<void> => {
  const value = page.locator(`#${id}Value`);
  const button = page.locator(`#${id}ComputeButton`);
  await expect.poll(async () => {
    if (/^[a-f0-9]+$/.test(await value.textContent() ?? "")) return "computed";
    return await button.isEnabled() ? "ready" : "working";
  }).not.toBe("working");
  if (!/^[a-f0-9]+$/.test(await value.textContent() ?? "")) await button.click();
};

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
  await expect(page.locator("#fileAnalysisDurationDetail")).not.toHaveText("");
  const continuous = page.locator(".workspaceContinuous");
  if (await continuous.count()) {
    const back = page.locator("#workspaceReportButton");
    if (await back.isVisible()) await back.click();
    await expect(page.getByRole("heading", { name: title, exact: true }))
      .toBeVisible();
    return;
  }
  await page.locator("#workspaceNavigation button").filter({
    has: page.getByText(title, { exact: true })
  }).click();
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
