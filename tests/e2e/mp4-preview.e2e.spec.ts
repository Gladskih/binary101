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
  await expect(page.locator("#analysisValue")).toContainText("MP4 / ISO-BMFF container");
};

const installDeferredMediaError = async (page: Page): Promise<void> => {
  await page.evaluate(() => {
    // Hold browser media error listeners until the test explicitly invokes one.
    const install = (prototype: EventTarget): void => {
      const addEventListener = prototype.addEventListener;
      prototype.addEventListener = function(
        this: EventTarget,
        type: string,
        listener: EventListenerOrEventListenerObject | null,
        options?: boolean | AddEventListenerOptions
      ): void {
        if (type === "error" && listener) {
          Reflect.set(globalThis, "triggerPreviewMediaError", () => {
            const event = new Event("error");
            if (typeof listener === "function") {
              listener.call(this, event);
            } else {
              listener.handleEvent(event);
            }
          });
          return;
        }
        addEventListener.call(this, type, listener, options);
      };
    };
    install(HTMLVideoElement.prototype);
    install(HTMLSourceElement.prototype);
  });
};

const triggerDeferredMediaError = async (page: Page): Promise<void> => {
  await page.evaluate(() => {
    const isTrigger = (value: unknown): value is (() => void) => typeof value === "function";
    const trigger: unknown = Reflect.get(globalThis, "triggerPreviewMediaError");
    if (!isTrigger(trigger)) {
      throw new Error("Preview error listener was not registered.");
    }
    trigger();
  });
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
    await installDeferredMediaError(page);
    await page.evaluate(() => {
      // `maybe` means the browser might support the MIME type:
      // https://html.spec.whatwg.org/multipage/media.html#dom-htmlmediaelement-canplaytype
      HTMLMediaElement.prototype.canPlayType =
        mimeType => (mimeType === "video/mp4" ? "maybe" : "");
    });
    const { file, upload } = toUpload();
    await page.setInputFiles("#fileInput", upload);

    await expectMp4Details(page, file.name);
    const videoPreview = page.locator(".videoPreview video");
    await expect(videoPreview).toBeVisible();
    await triggerDeferredMediaError(page);
    await expect(videoPreview).toHaveCount(0);
    await expect(page.locator("#statusMessage")).toHaveText(
      "Preview not shown: browser cannot play this video format inline."
    );
  });
});
