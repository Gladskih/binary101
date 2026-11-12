import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { test } from "node:test";
import { setImmediate } from "node:timers/promises";
import {
  createHashControlsFixture, createClipboardDigestText, createHashValueElement, getHashAlgorithm,
  nodeDigestNameForHashAlgorithm, createNativeHashFile, createFallbackHashFile,
  installNativeDigestProbe, installClipboardStub, clickFixture, nextText
} from "../../helpers/hash-controls-fixture.js";
import {
  HASH_ALGORITHMS,
  computeAndDisplayHash,
  copyHashToClipboard,
  resetHashDisplay,
  createHashControls,
  attachHashControls
} from "../../../ui/hash-controls.js";

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

  assert.equal(valueElement.textContent, "Hash failed: boom");
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

void test("bound controls compute the active file and report successful copying locally", async () => {
  const state = createHashControlsFixture();
  Object.defineProperty(state.copyButtonElement, "dataset", { value: {} });
  const status = { textContent: "", dataset: {} } as HTMLElement;
  const compute = clickFixture(state.buttonElement);
  const copy = clickFixture(state.copyButtonElement);
  const file = new File(["abc"], "sample");
  const value = nextText(state.valueElement);
  let clipboard = "";
  const restore = installClipboardStub(async text => { clipboard = text; });
  attachHashControls([{ ...state.controls, algorithm: getHashAlgorithm("sha256") }], () => file, status);

  try {
    compute();
    assert.equal(await value, createHash("sha256").update("abc").digest("hex"));
    const message = nextText(status);
    copy();
    assert.equal(await message, "SHA-256 copied.");
    assert.equal(clipboard, state.valueElement.textContent);
    assert.equal(state.copyButtonElement.dataset["copyState"], "copied");
    resetHashDisplay(state.controls);
    assert.equal(state.copyButtonElement.dataset["copyState"], undefined);
  } finally {
    restore();
  }
});

void test("bound copy failures produce a local error rather than a success indicator", async () => {
  const state = createHashControlsFixture();
  Object.defineProperty(state.copyButtonElement, "dataset", { value: {} });
  const status = { textContent: "", dataset: {} } as HTMLElement;
  clickFixture(state.buttonElement);
  const copy = clickFixture(state.copyButtonElement);
  const message = nextText(status);
  const restore = installClipboardStub(async () => { throw new Error("denied"); });
  attachHashControls([{ ...state.controls, algorithm: getHashAlgorithm("sha256") }], () => null, status);

  try {
    copy();
    assert.equal(await message, "Clipboard copy failed.");
    assert.equal(status.dataset["state"], "failed");
    assert.equal(state.copyButtonElement.dataset["copyState"], "failed");
  } finally {
    restore();
  }
});

void test("hash controls reserve the full digest length without including it in copied data", () => {
  const elements = new Map<string, HTMLElement>();
  for (const algorithm of HASH_ALGORITHMS) {
    const state = createHashControlsFixture(algorithm.label);
    elements.set(`${algorithm.id}Value`, state.valueElement);
    elements.set(`${algorithm.id}ComputeButton`, state.buttonElement);
    elements.set(`${algorithm.id}CopyButton`, state.copyButtonElement);
    elements.set(`${algorithm.id}Reserved`, { textContent: "" } as HTMLElement);
    if ("nativeAlgorithm" in algorithm) elements.set(`${algorithm.id}NativeBadge`, state.nativeHashBadgeElement);
  }
  const root = { getElementById: (id: string) => elements.get(id) ?? null } as Document;

  const controls = createHashControls(root);

  assert.equal(controls.length, 8);
  assert.equal(elements.get("md5Reserved")!.textContent!.length, 32);
  assert.equal(elements.get("sha512Reserved")!.textContent!.length, 128);
  assert.equal(elements.get("sha512Value")!.textContent, "");
});

void test("bound controls ignore failed reads and copy completions after the file changes", async () => {
  const state = createHashControlsFixture();
  Object.defineProperty(state.copyButtonElement, "dataset", { value: {} });
  const status = { textContent: "", dataset: {} } as HTMLElement;
  const compute = clickFixture(state.buttonElement);
  const copy = clickFixture(state.copyButtonElement);
  let file: File | null = new File(["abc"], "first");
  let failRead: (error: Error) => void = () => {};
  Object.defineProperty(file, "arrayBuffer", { value: () => new Promise<ArrayBuffer>((_, reject) => {
    failRead = reject;
  }) });
  let finishCopy: () => void = () => {};
  const restore = installClipboardStub(() => new Promise<void>(resolve => { finishCopy = resolve; }));
  attachHashControls([{ ...state.controls, algorithm: getHashAlgorithm("sha256") }], () => file, status);

  try {
    compute();
    copy();
    file = null;
    resetHashDisplay(state.controls);
    failRead(new Error("Stale read failed"));
    finishCopy();
    await setImmediate();
    assert.equal(state.valueElement.textContent, "");
    assert.equal(state.buttonElement.disabled, false);
    assert.equal(state.copyButtonElement.dataset["copyState"], undefined);
    assert.equal(status.textContent, "");
  } finally {
    restore();
  }
});
