import { expect, test, type Page } from "@playwright/test";
import { createWebmWithDurationMismatch } from "../fixtures/webm-duration-fixtures.js";

const inspectMedia = async (page: Page): Promise<void> => {
  const file = createWebmWithDurationMismatch();
  await page.setInputFiles("#fileInput", { name: file.name, mimeType: file.type,
    buffer: Buffer.from(file.data) });
};

test("WebM analysis uses a local worker and displays its parsed result", async ({ page }) => {
  const workers: string[] = [];
  const errors: string[] = [];
  page.on("worker", worker => workers.push(worker.url()));
  page.on("pageerror", error => errors.push(error.message));
  await page.goto("/");

  await inspectMedia(page);

  await expect(page.locator("#workspaceMobileView")).toContainText("Tracks");
  expect(workers.some(url => url.includes("webm-worker"))).toBe(true);
  await expect(page.locator("#fileAnalysisProgress")).toBeHidden();
  expect(errors).toEqual([]);
});

test("failed WebM workers report an error, release progress and allow another file", async ({ page }) => {
  const workerUrl = /\/webm-worker(?:-[^/]+\.js|\.ts)(?:\?|$)/;
  const errors: string[] = [];
  page.on("pageerror", error => errors.push(error.message));
  await page.route(workerUrl, route => route.abort());
  await page.goto("/");

  await inspectMedia(page);

  await expect(page.locator("#statusMessage")).toContainText("Unable to read file");
  await expect(page.locator("#fileAnalysisProgress")).toBeHidden();
  await page.unroute(workerUrl);
  await inspectMedia(page);
  await expect(page.locator("#workspaceMobileView")).toContainText("Tracks");
  expect(errors).toEqual([]);
});

test("finishing a scan preserves a file tool opened while analysis was pending", async ({ page }) => {
  let release = (): void => {};
  const loading = new Promise<void>(resolve => { release = resolve; });
  await page.route(/\/webm-worker(?:-[^/]+\.js|\.ts)(?:\?|$)/, async route => {
    await loading;
    await route.continue();
  });
  await page.goto("/");
  await inspectMedia(page);
  await expect(page.locator("#fileAnalysisProgress")).toBeVisible();
  await page.locator("#fileHashesButton").click();

  release();

  await expect(page.locator("#fileAnalysisDurationDetail")).not.toHaveText("");
  await expect(page.locator("#workspaceTitle")).toHaveText("File hashes");
});
