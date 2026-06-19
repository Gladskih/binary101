import { expect, test } from "@playwright/test";
import type { Page } from "@playwright/test";
import { createMp4File } from "../fixtures/mp4-fixtures.js";

const toUpload = () => {
  const file = createMp4File();
  return {
    file,
    upload: {
      name: file.name,
      mimeType: file.type,
      buffer: Buffer.from(file.data)
    }
  };
};

const expectMp4Details = async (page: Page, fileName: string): Promise<void> => {
  await expect(page.locator("#fileInfoCard")).toBeVisible();
  await expect(page.locator("#fileNameDetail")).toHaveText(fileName);
  await expect(page.locator("#fileBinaryTypeDetail")).toHaveText(
    "MP4/QuickTime container (ISO-BMFF)"
  );
  await expect(page.locator("#peDetailsValue")).toContainText("MP4 / ISO-BMFF container");
};

test.describe("MP4 previews", () => {
  test.beforeEach(async ({ page }) => {
    await page.goto("/");
    await expect(page.getByRole("heading", { name: "Local File Inspector" })).toBeVisible();
  });

  void test("suppresses previews unsupported by the browser", async ({ page }) => {
    await page.evaluate(() => {
      // HTML canPlayType returns an empty string for unsupported MIME types:
      // https://html.spec.whatwg.org/multipage/media.html#dom-htmlmediaelement-canplaytype
      HTMLMediaElement.prototype.canPlayType = () => "";
    });
    const { file, upload } = toUpload();
    await page.setInputFiles("#fileInput", upload);

    await expectMp4Details(page, file.name);
    await expect(page.locator(".videoPreview video")).toHaveCount(0);
  });

  void test("removes previews after a browser playback error", async ({ page }) => {
    await page.evaluate(() => {
      // Force preview creation so the UI reacts to the subsequent media error.
      HTMLMediaElement.prototype.canPlayType =
        mimeType => (mimeType === "video/mp4" ? "maybe" : "");
    });
    const { file, upload } = toUpload();
    await page.setInputFiles("#fileInput", upload);

    await expectMp4Details(page, file.name);
    const videoPreview = page.locator(".videoPreview video");
    await expect(videoPreview).toBeVisible();
    await videoPreview.dispatchEvent("error");
    await expect(videoPreview).toHaveCount(0);
    await expect(page.locator("#statusMessage")).toHaveText(
      "Preview not shown: browser cannot play this video format inline."
    );
  });
});
