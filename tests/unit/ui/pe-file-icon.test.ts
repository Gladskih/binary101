"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import type { ParseForUiResult } from "../../../analyzers/index.js";
import { attachPeFileIconGuard, renderPeFileIcon } from "../../../ui/pe-file-icon.js";
import { createPreviewLangEntry } from "../../helpers/pe-resource-preview-fixture.js";

const iconDataUrl = "data:image/x-icon;base64,AAE=";

const createPeResult = (
  previewDataUrl?: string,
  typeName = "GROUP_ICON",
  previewKind = "image"
): ParseForUiResult => ({
  analyzer: "pe",
  parsed: {
    resources: {
      detail: [{
        typeName,
        entries: [{
          id: null,
          name: null,
          langs: [{
            ...createPreviewLangEntry(),
            previewKind,
            previewMime: "image/x-icon",
            ...(previewDataUrl ? { previewDataUrl } : {})
          }]
        }]
      }]
    }
  }
} as unknown as ParseForUiResult);

const createElements = (): { image: HTMLImageElement; wrapper: HTMLElement } => {
  const image = {
    alt: "",
    src: "",
    removeAttribute(name: string) {
      if (name === "src") this.src = "";
    }
  } as HTMLImageElement;
  return { image, wrapper: { hidden: true } as HTMLElement };
};

const createGuardElements = (alpha: number | null): {
  image: HTMLImageElement;
  trigger: (type: "error" | "load") => void;
  wrapper: HTMLElement;
} => {
  const listeners = new Map<string, () => void>();
  const fakeImage = {
    alt: "Icon embedded in sample.exe",
    src: iconDataUrl,
    naturalWidth: 32,
    naturalHeight: 32,
    ownerDocument: {
      createElement() {
        return {
          getContext() {
            return {
              drawImage() {},
              getImageData() {
                if (alpha == null) throw new Error("Canvas readback failed.");
                // RGB is incidental; alpha is the visibility condition under test.
                return { data: new Uint8ClampedArray([0, 0, 0, alpha]) };
              }
            };
          },
          width: 0,
          height: 0
        };
      }
    },
    addEventListener(type: string, listener: () => void) {
      listeners.set(type, listener);
    },
    removeAttribute(name: string) {
      if (name === "src") fakeImage.src = "";
    }
  };
  const image = fakeImage as unknown as HTMLImageElement;
  return {
    image,
    trigger: type => listeners.get(type)!(),
    wrapper: { hidden: false } as HTMLElement
  };
};

void test("renderPeFileIcon shows the GROUP_ICON preview for PE files", () => {
  const { image, wrapper } = createElements();

  renderPeFileIcon(createPeResult(iconDataUrl), "sample.exe", image, wrapper);

  assert.equal(wrapper.hidden, false);
  assert.equal(image.src, iconDataUrl);
  assert.equal(image.alt, "Icon embedded in sample.exe");
});

void test("renderPeFileIcon clears stale icons for missing previews and non-PE results", () => {
  const { image, wrapper } = createElements();
  image.src = iconDataUrl;
  image.alt = "stale";
  wrapper.hidden = false;

  renderPeFileIcon(createPeResult(), "missing.exe", image, wrapper);
  assert.equal(wrapper.hidden, true);
  assert.equal(image.src, "");
  assert.equal(image.alt, "");

  renderPeFileIcon({ analyzer: null, parsed: null }, "plain.txt", image, wrapper);
  assert.equal(wrapper.hidden, true);

  renderPeFileIcon({ analyzer: "pe", parsed: {} } as unknown as ParseForUiResult, "rom.bin", image, wrapper);
  assert.equal(wrapper.hidden, true);
});

void test("renderPeFileIcon rejects non-group, non-image, and non-image-URL previews", () => {
  const { image, wrapper } = createElements();

  renderPeFileIcon(createPeResult(iconDataUrl, "BITMAP"), "sample.exe", image, wrapper);
  assert.equal(wrapper.hidden, true);

  renderPeFileIcon(createPeResult(iconDataUrl, "GROUP_ICON", "text"), "sample.exe", image, wrapper);
  assert.equal(wrapper.hidden, true);

  renderPeFileIcon(createPeResult("javascript:alert(1)"), "sample.exe", image, wrapper);
  assert.equal(wrapper.hidden, true);
});

void test("renderPeFileIcon uses an accessible fallback when the PE file has no name", () => {
  const { image, wrapper } = createElements();

  renderPeFileIcon(createPeResult(iconDataUrl), "", image, wrapper);

  assert.equal(image.alt, "Icon embedded in PE file");
});

void test("attachPeFileIconGuard removes a transparent icon and its reserved space", () => {
  // Alpha 0 marks a fully transparent RGBA pixel.
  const { image, trigger, wrapper } = createGuardElements(0);

  attachPeFileIconGuard(image, wrapper);
  trigger("load");

  assert.equal(wrapper.hidden, true);
  assert.equal(image.src, "");
  assert.equal(image.alt, "");
});

void test("attachPeFileIconGuard keeps an icon with visible pixels", () => {
  // Alpha 255 marks a fully opaque RGBA pixel.
  const { image, trigger, wrapper } = createGuardElements(255);

  attachPeFileIconGuard(image, wrapper);
  trigger("load");

  assert.equal(wrapper.hidden, false);
  assert.equal(image.src, iconDataUrl);
});

void test("attachPeFileIconGuard removes an icon that the browser cannot decode", () => {
  // Alpha is irrelevant because the error handler runs before pixel inspection.
  const { image, trigger, wrapper } = createGuardElements(255);

  attachPeFileIconGuard(image, wrapper);
  trigger("error");

  assert.equal(wrapper.hidden, true);
  assert.equal(image.src, "");
});

void test("attachPeFileIconGuard removes an icon when pixel inspection fails", () => {
  const { image, trigger, wrapper } = createGuardElements(null);

  attachPeFileIconGuard(image, wrapper);
  trigger("load");

  assert.equal(wrapper.hidden, true);
  assert.equal(image.src, "");
});
