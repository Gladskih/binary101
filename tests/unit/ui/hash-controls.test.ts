"use strict";

import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { test } from "node:test";
import {
  HASH_ALGORITHMS,
  computeAndDisplayHash,
  copyHashToClipboard,
  resetHashDisplay,
  type HashAlgorithmOption,
  type HashControls
} from "../../../ui/hash-controls.js";

const createHashControlsFixture = (label = "SHA-256"): {
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
    controls: { label, valueElement, buttonElement, copyButtonElement },
    valueElement,
    buttonElement,
    copyButtonElement
  };
};

const createClipboardDigestText = (): string => {
  const bytes = new Uint8Array(8);
  bytes.forEach((_, index) => {
    bytes[index] = index;
  });
  return Array.from(bytes, byte => byte.toString(16).padStart(2, "0")).join("");
};
const createHashValueElement = (textContent: string): HTMLElement =>
  ({ textContent }) as HTMLElement;

const getHashAlgorithm = (id: string): HashAlgorithmOption => {
  const algorithm = HASH_ALGORITHMS.find(entry => entry.id === id);
  assert.ok(algorithm);
  return algorithm;
};

const nodeDigestNameForHashAlgorithm = (algorithm: HashAlgorithmOption): string => {
  if (algorithm.id === "sha512224") return "sha512-224";
  if (algorithm.id === "sha512256") return "sha512-256";
  return algorithm.id;
};

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
  const sha512 = createHashControlsFixture("SHA-512").controls;
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
  const expectedDigest = createHash("sha256").update(fileBytes).digest("hex");

  await computeAndDisplayHash(getHashAlgorithm("sha256"), file, controls);

  assert.equal(valueElement.textContent, expectedDigest);
  assert.equal(copyButtonElement.hidden, false);
  assert.equal(buttonElement.hidden, true);
});

void test("computeAndDisplayHash supports every visible hash algorithm", async () => {
  const fileBytes = new TextEncoder().encode("abc");
  const file = new File([fileBytes], "abc.bin");

  for (const algorithm of HASH_ALGORITHMS) {
    const { controls, valueElement } = createHashControlsFixture();
    const expectedDigest = createHash(nodeDigestNameForHashAlgorithm(algorithm))
      .update(fileBytes)
      .digest("hex");
    await computeAndDisplayHash(algorithm, file, controls);
    assert.equal(valueElement.textContent, expectedDigest);
  }
});

void test("computeAndDisplayHash reports when no file is selected", async () => {
  const { controls, valueElement, buttonElement, copyButtonElement } = createHashControlsFixture();

  await computeAndDisplayHash(getHashAlgorithm("sha256"), null, controls);

  assert.equal(valueElement.textContent, "No file selected.");
  assert.equal(buttonElement.disabled, false);
  assert.equal(buttonElement.textContent, "Compute SHA-256");
  assert.equal(copyButtonElement.hidden, true);
});

void test("computeAndDisplayHash surfaces failures and leaves the button retryable", async () => {
  const { controls, valueElement, buttonElement, copyButtonElement } = createHashControlsFixture();
  const file = {
    stream: () => ({
      getReader: () => ({
        read: async () => { throw new Error("boom"); },
        releaseLock: () => undefined
      })
    })
  } as unknown as File;

  await computeAndDisplayHash(getHashAlgorithm("sha256"), file, controls);

  assert.match(valueElement.textContent || "", /^Hash failed:/);
  assert.match(valueElement.textContent || "", /boom$/);
  assert.equal(buttonElement.disabled, false);
  assert.equal(buttonElement.textContent, "Retry");
  assert.equal(copyButtonElement.hidden, true);
});

void test("copyHashToClipboard reports success when clipboard writes succeed", async () => {
  let copiedText = "";
  const hashText = createClipboardDigestText();
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
  const hashText = createClipboardDigestText();
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
