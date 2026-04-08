"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { copyManifestPreviewToClipboard } from "../../ui/manifest-preview-copy.js";

type ClipboardStub = (text: string) => Promise<void>;

const installClipboardStub = (writeText: ClipboardStub): (() => void) => {
  const globals = globalThis as unknown as Record<string, unknown>;
  const hadNavigator = Object.prototype.hasOwnProperty.call(globals, "navigator");
  const originalNavigator = globals["navigator"];
  Object.defineProperty(globals, "navigator", {
    configurable: true,
    value: { clipboard: { writeText } }
  });
  return () => {
    if (hadNavigator) {
      Object.defineProperty(globals, "navigator", {
        configurable: true,
        value: originalNavigator
      });
      return;
    }
    Reflect.deleteProperty(globals, "navigator");
  };
};

const createFixture = (manifestText = "<assembly />") => {
  const source = { textContent: manifestText };
  const preview = {
    closest: () => null,
    querySelector: (selector: string) => (selector === "[data-manifest-copy-source]" ? source : null)
  };
  const button = {
    closest: (selector: string) => (selector === "[data-manifest-preview]" ? preview : null)
  };
  const target = {
    closest: (selector: string) => (selector === "[data-manifest-copy-button]" ? button : null)
  };
  return { source, target };
};

void test("copyManifestPreviewToClipboard copies the manifest source text", async () => {
  let copiedText = "";
  const restoreNavigator = installClipboardStub(async (text: string): Promise<void> => {
    copiedText = text;
  });

  try {
    const fixture = createFixture("synthetic-manifest");
    const result = await copyManifestPreviewToClipboard(fixture.target as never);
    assert.equal(result, "copied");
    assert.equal(copiedText, "synthetic-manifest");
  } finally {
    restoreNavigator();
  }
});

void test("copyManifestPreviewToClipboard reports failure when the preview source is missing", async () => {
  const restoreNavigator = installClipboardStub(async (): Promise<void> => {});

  try {
    const button = {
      closest: (selector: string) => (selector === "[data-manifest-preview]" ? { querySelector: () => null } : null)
    };
    const target = {
      closest: (selector: string) => (selector === "[data-manifest-copy-button]" ? button : null)
    };
    const result = await copyManifestPreviewToClipboard(target as never);
    assert.equal(result, "failed");
  } finally {
    restoreNavigator();
  }
});

void test("copyManifestPreviewToClipboard ignores unrelated clicks", async () => {
  const result = await copyManifestPreviewToClipboard({ closest: () => null } as never);
  assert.equal(result, "ignored");
});
