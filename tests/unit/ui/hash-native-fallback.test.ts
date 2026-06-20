"use strict";

import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { test } from "node:test";
import { HASH_ALGORITHMS, computeAndDisplayHash, type HashControls } from "../../../ui/hash-controls.js";

const getSha256 = () => {
  const algorithm = HASH_ALGORITHMS.find(entry => entry.id === "sha256");
  assert.ok(algorithm);
  return algorithm;
};

const createControls = (): { controls: HashControls; fallback: HTMLElement; value: HTMLElement } => {
  const fallback = { hidden: true } as HTMLElement;
  const value = { textContent: "" } as HTMLElement;
  return {
    controls: {
      label: "SHA-256",
      valueElement: value,
      buttonElement: { hidden: false, disabled: false, textContent: "Compute SHA-256" } as HTMLButtonElement,
      copyButtonElement: { hidden: true } as HTMLButtonElement,
      nativeFallbackElement: fallback
    },
    fallback,
    value
  };
};

void test("retries native hashes with noble after NotReadableError", async () => {
  const bytes = new TextEncoder().encode("abc");
  const { controls, fallback, value } = createControls();
  const file = {
    arrayBuffer: async () => { throw new DOMException("file is too large", "NotReadableError"); },
    stream: () => new Blob([bytes]).stream()
  } as unknown as File;

  await computeAndDisplayHash(getSha256(), file, controls);

  assert.equal(value.textContent, createHash("sha256").update(bytes).digest("hex"));
  assert.equal(fallback.hidden, false);
});

void test("does not retry native hashes after other errors", async () => {
  const { controls, fallback, value } = createControls();
  const file = {
    arrayBuffer: async () => { throw new Error("boom"); },
    stream: () => { throw new Error("Noble must not run."); }
  } as unknown as File;

  await computeAndDisplayHash(getSha256(), file, controls);

  assert.match(value.textContent || "", /boom$/);
  assert.equal(fallback.hidden, true);
});
