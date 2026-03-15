"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import {
  computeAndDisplayHash,
  copyHashToClipboard,
  resetHashDisplay,
  type HashControls
} from "../../ui/hash-controls.js";

const SHA256_ABC_HEX =
  "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

const createHashControls = (): HashControls => ({
  valueElement: { textContent: "stale" } as HTMLElement,
  buttonElement: {
    hidden: true,
    disabled: true,
    textContent: "Busy"
  } as HTMLButtonElement,
  copyButtonElement: { hidden: false } as HTMLButtonElement
});

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
  const sha256 = createHashControls();
  const sha512 = createHashControls();

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
  const controls = createHashControls();
  // FIPS 180-4 SHA-256 test vector for the ASCII string "abc".
  const file = new File([new TextEncoder().encode("abc")], "abc.bin");

  await computeAndDisplayHash("SHA-256", file, controls);

  assert.equal(controls.valueElement.textContent, SHA256_ABC_HEX);
  assert.equal(controls.copyButtonElement.hidden, false);
  assert.equal(controls.buttonElement.hidden, true);
});

void test("computeAndDisplayHash reports when no file is selected", async () => {
  const controls = createHashControls();

  await computeAndDisplayHash("SHA-256", null, controls);

  assert.equal(controls.valueElement.textContent, "No file selected.");
  assert.equal(controls.buttonElement.disabled, true);
  assert.equal(controls.buttonElement.textContent, "Busy");
});

void test("computeAndDisplayHash surfaces failures and leaves the button retryable", async () => {
  const controls = createHashControls();
  const file = {
    arrayBuffer: async (): Promise<ArrayBuffer> => {
      throw new Error("boom");
    }
  } as File;

  await computeAndDisplayHash("SHA-256", file, controls);

  assert.match(controls.valueElement.textContent || "", /^Hash failed: Error: Error: boom$/);
  assert.equal(controls.buttonElement.disabled, false);
  assert.equal(controls.buttonElement.textContent, "Retry");
  assert.equal(controls.copyButtonElement.hidden, true);
});

void test("copyHashToClipboard reports success when clipboard writes succeed", async () => {
  let copiedText = "";
  const restoreNavigator = installClipboardStub(async (text: string): Promise<void> => {
    copiedText = text;
  });

  try {
    const result = await copyHashToClipboard({ textContent: "feedface" } as HTMLElement);
    assert.equal(result, "copied");
    assert.equal(copiedText, "feedface");
  } finally {
    restoreNavigator();
  }
});

void test("copyHashToClipboard reports failure when clipboard writes reject", async () => {
  const restoreNavigator = installClipboardStub(async (): Promise<void> => {
    throw new Error("denied");
  });

  try {
    const result = await copyHashToClipboard({ textContent: "feedface" } as HTMLElement);
    assert.equal(result, "failed");
  } finally {
    restoreNavigator();
  }
});
