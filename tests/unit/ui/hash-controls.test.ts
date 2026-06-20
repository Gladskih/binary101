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
  nativeHashBadgeElement: HTMLButtonElement;
} => {
  const valueElement = { textContent: "" } as HTMLElement;
  const buttonElement = {
    hidden: false,
    disabled: false,
    textContent: "Compute SHA-256"
  } as HTMLButtonElement;
  const copyButtonElement = { hidden: true } as HTMLButtonElement;
  const nativeHashBadgeElement = {
    classList: { add: () => undefined, remove: () => undefined },
    parentElement: null,
    textContent: "🍃",
    title: "",
    setAttribute: () => undefined
  } as unknown as HTMLButtonElement;
  return {
    controls: { label, valueElement, buttonElement, copyButtonElement, nativeHashBadgeElement },
    valueElement,
    buttonElement,
    copyButtonElement,
    nativeHashBadgeElement
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

const createNativeHashFile = (bytes: Uint8Array<ArrayBuffer>): File => ({
  arrayBuffer: async () =>
    bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength),
  stream: () => { throw new Error("Native hash must not read a stream."); }
}) as unknown as File;

const createFallbackHashFile = (bytes: Uint8Array<ArrayBuffer>): File => ({
  arrayBuffer: async () => { throw new Error("Fallback hash must not read an ArrayBuffer."); },
  stream: () => new Blob([bytes]).stream()
}) as unknown as File;

const installNativeDigestProbe = (): {
  algorithms: AlgorithmIdentifier[];
  restore: () => void;
} => {
  const globals = globalThis as unknown as Record<string, unknown>;
  const cryptoDescriptor = Object.getOwnPropertyDescriptor(globals, "crypto");
  const nativeDigest = crypto.subtle.digest.bind(crypto.subtle);
  const algorithms: AlgorithmIdentifier[] = [];
  Object.defineProperty(globals, "crypto", {
    configurable: true,
    value: {
      subtle: {
        digest: async (
          algorithm: AlgorithmIdentifier,
          data: BufferSource
        ): Promise<ArrayBuffer> => {
          algorithms.push(algorithm);
          return nativeDigest(algorithm, data);
        }
      }
    }
  });
  return {
    algorithms,
    restore: () => {
      if (cryptoDescriptor) Object.defineProperty(globals, "crypto", cryptoDescriptor);
    }
  };
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

void test("computeAndDisplayHash uses WebCrypto input for browser-native algorithms", async () => {
  const fileBytes = new TextEncoder().encode("abc");
  const probe = installNativeDigestProbe();

  try {
    for (const id of ["sha1", "sha256", "sha384", "sha512"]) {
      const algorithm = getHashAlgorithm(id);
      const { controls, valueElement } = createHashControlsFixture(algorithm.label);
      await computeAndDisplayHash(algorithm, createNativeHashFile(fileBytes), controls);
      assert.equal(
        valueElement.textContent,
        createHash(nodeDigestNameForHashAlgorithm(algorithm)).update(fileBytes).digest("hex")
      );
    }
    assert.deepEqual(probe.algorithms, ["SHA-1", "SHA-256", "SHA-384", "SHA-512"]);
  } finally {
    probe.restore();
  }
});

void test("computeAndDisplayHash streams algorithms without browser-native support", async () => {
  const fileBytes = new TextEncoder().encode("abc");

  for (const id of ["md5", "sha224", "sha512224", "sha512256"]) {
    const algorithm = getHashAlgorithm(id);
    const { controls, valueElement } = createHashControlsFixture(algorithm.label);
    await computeAndDisplayHash(algorithm, createFallbackHashFile(fileBytes), controls);
    assert.equal(
      valueElement.textContent,
      createHash(nodeDigestNameForHashAlgorithm(algorithm)).update(fileBytes).digest("hex")
    );
  }
});

void test("computeAndDisplayHash ignores a result after the selected file changes", async () => {
  const { controls, valueElement, buttonElement, copyButtonElement } = createHashControlsFixture();
  const fileBytes = new TextEncoder().encode("abc");
  let resolveArrayBuffer: (buffer: ArrayBuffer) => void = () => undefined;
  const file = {
    arrayBuffer: () => new Promise<ArrayBuffer>(resolve => { resolveArrayBuffer = resolve; })
  } as unknown as File;
  const computing = computeAndDisplayHash(getHashAlgorithm("sha256"), file, controls, () => false);

  resetHashDisplay(controls);
  resolveArrayBuffer(fileBytes.buffer);
  await computing;

  assert.equal(valueElement.textContent, "");
  assert.equal(buttonElement.hidden, false);
  assert.equal(buttonElement.disabled, false);
  assert.equal(copyButtonElement.hidden, true);
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

  await computeAndDisplayHash(getHashAlgorithm("md5"), file, controls);

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
