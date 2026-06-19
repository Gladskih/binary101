"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import type { ParseForUiResult } from "../../../analyzers/index.js";
import { renderPeFileIcon } from "../../../ui/pe-file-icon.js";

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
          id: 1,
          name: null,
          langs: [{
            lang: 1033,
            size: 20,
            codePage: 0,
            dataRVA: 4096,
            dataFileOffset: 512,
            reserved: 0,
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
