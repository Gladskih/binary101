"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import {
  computeAndDisplayHash,
  copyHashToClipboard,
  resetHashDisplay,
  type HashControls
} from "../../ui/hash-controls.js";

const createHashControlsFixture = (): {
  controls: HashControls;
  valueElement: HTMLElement;
  buttonElement: HTMLButtonElement;
  copyButtonElement: HTMLButtonElement;
} => {
  const valueElement = { textContent: "" } as HTMLElement;
  const buttonElement = {
    hidden: false,
    disabled: false,
    textContent: "Compute SHA-256"
  } as HTMLButtonElement;
  const copyButtonElement = { hidden: true } as HTMLButtonElement;
  return {
    controls: { valueElement, buttonElement, copyButtonElement },
    valueElement,
    buttonElement,
    copyButtonElement
  };
};

const createHashText = (): string => "0123456789abcdef";
const createHashValueElement = (textContent: string): HTMLElement =>
  ({ textContent }) as HTMLElement;

const installClipboardStub = (
  writeText: (text: string) => Promise<void>
): (() => void) => {
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

void test("resetHashDisplay restores both hash controls to their initial state", () => {
  const sha256 = createHashControlsFixture().controls;
  const sha512 = createHashControlsFixture().controls;
  sha256.valueElement.textContent = "stale";
  sha256.buttonElement.hidden = true;
  sha256.buttonElement.disabled = true;
  sha256.buttonElement.textContent = "Busy";
  sha256.copyButtonElement.hidden = false;
  sha512.valueElement.textContent = "stale";
  sha512.buttonElement.hidden = true;
  sha512.buttonElement.disabled = true;
  sha512.buttonElement.textContent = "Busy";
  sha512.copyButtonElement.hidden = false;

  resetHashDisplay(sha256, sha512);

  assert.equal(sha256.valueElement.textContent, "");
  assert.equal(sha512.valueElement.textContent, "");
  assert.equal(sha256.copyButtonElement.hidden, true);
  assert.equal(sha512.copyButtonElement.hidden, true);
  assert.equal(sha256.buttonElement.hidden, false);
  assert.equal(sha512.buttonElement.hidden, false);
  assert.equal(sha256.buttonElement.disabled, false);
  assert.equal(sha512.buttonElement.disabled, false);
  assert.equal(sha256.buttonElement.textContent, "Compute SHA-256");
  assert.equal(sha512.buttonElement.textContent, "Compute SHA-512");
});

void test("computeAndDisplayHash renders the computed digest and enables copy", async () => {
  const { controls, valueElement, buttonElement, copyButtonElement } = createHashControlsFixture();
  const fileBytes = new TextEncoder().encode("abc");
  const file = new File([fileBytes], "abc.bin");
  const expectedDigest = Buffer.from(await crypto.subtle.digest("SHA-256", fileBytes)).toString("hex");

  await computeAndDisplayHash("SHA-256", file, controls);

  assert.equal(valueElement.textContent, expectedDigest);
  assert.equal(copyButtonElement.hidden, false);
  assert.equal(buttonElement.hidden, true);
});

void test("computeAndDisplayHash reports when no file is selected", async () => {
  const { controls, valueElement, buttonElement, copyButtonElement } = createHashControlsFixture();

  await computeAndDisplayHash("SHA-256", null, controls);

  assert.equal(valueElement.textContent, "No file selected.");
  assert.equal(buttonElement.disabled, false);
  assert.equal(buttonElement.textContent, "Compute SHA-256");
  assert.equal(copyButtonElement.hidden, true);
});

void test("computeAndDisplayHash surfaces failures and leaves the button retryable", async () => {
  const { controls, valueElement, buttonElement, copyButtonElement } = createHashControlsFixture();
  const file = {
    arrayBuffer: async (): Promise<ArrayBuffer> => {
      throw new Error("boom");
    }
  } as File;

  await computeAndDisplayHash("SHA-256", file, controls);

  assert.match(valueElement.textContent || "", /^Hash failed:/);
  assert.match(valueElement.textContent || "", /boom$/);
  assert.equal(buttonElement.disabled, false);
  assert.equal(buttonElement.textContent, "Retry");
  assert.equal(copyButtonElement.hidden, true);
});

void test("copyHashToClipboard reports success when clipboard writes succeed", async () => {
  let copiedText = "";
  const hashText = createHashText();
  const restoreNavigator = installClipboardStub(async (text: string): Promise<void> => {
    copiedText = text;
  });

  try {
    const result = await copyHashToClipboard(createHashValueElement(hashText));
    assert.equal(result, "copied");
    assert.equal(copiedText, hashText);
  } finally {
    restoreNavigator();
  }
});

void test("copyHashToClipboard reports failure when clipboard writes reject", async () => {
  const hashText = createHashText();
  const restoreNavigator = installClipboardStub(async (): Promise<void> => {
    throw new Error("denied");
  });

  try {
    const result = await copyHashToClipboard(createHashValueElement(hashText));
    assert.equal(result, "failed");
  } finally {
    restoreNavigator();
  }
});
