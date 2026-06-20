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

const createControls = (): {
  badgeAttributes: Map<string, string>;
  badge: HTMLButtonElement;
  controls: HashControls;
  popupAttributes: Map<string, string>;
  value: HTMLElement;
} => {
  const badgeAttributes = new Map<string, string>();
  const popupAttributes = new Map<string, string>();
  const badge = {
    classList: { add: () => undefined, remove: () => undefined },
    parentElement: {
      querySelector: () => ({ setAttribute: (name: string, value: string) =>
        popupAttributes.set(name, value) })
    },
    setAttribute: (name: string, value: string) => badgeAttributes.set(name, value),
    textContent: "🍃",
    title: ""
  } as unknown as HTMLButtonElement;
  const value = { textContent: "" } as HTMLElement;
  return {
    controls: {
      label: "SHA-256",
      valueElement: value,
      buttonElement: { hidden: false, disabled: false, textContent: "Compute SHA-256" } as HTMLButtonElement,
      copyButtonElement: { hidden: true } as HTMLButtonElement,
      nativeHashBadgeElement: badge
    },
    badgeAttributes,
    badge,
    popupAttributes,
    value
  };
};

void test("retries native hashes with noble after NotReadableError", async () => {
  const bytes = new TextEncoder().encode("abc");
  const { badge, badgeAttributes, controls, popupAttributes, value } = createControls();
  const file = {
    arrayBuffer: async () => { throw new DOMException("file is too large", "NotReadableError"); },
    stream: () => new Blob([bytes]).stream()
  } as unknown as File;

  await computeAndDisplayHash(getSha256(), file, controls);

  assert.equal(value.textContent, createHash("sha256").update(bytes).digest("hex"));
  assert.equal(badge.textContent, "🍂");
  assert.equal(badge.title, "Native crypto failed; fallback used.");
  assert.equal(badgeAttributes.get("aria-label"), "Show explanation: Native crypto failed; fallback used.");
  assert.equal(popupAttributes.get("aria-label"), "Native crypto failed; fallback used.");
});

void test("does not retry native hashes after other errors", async () => {
  const { badge, controls, value } = createControls();
  const file = {
    arrayBuffer: async () => { throw new Error("boom"); },
    stream: () => { throw new Error("Noble must not run."); }
  } as unknown as File;

  await computeAndDisplayHash(getSha256(), file, controls);

  assert.match(value.textContent || "", /boom$/);
  assert.equal(badge.textContent, "🍃");
});
