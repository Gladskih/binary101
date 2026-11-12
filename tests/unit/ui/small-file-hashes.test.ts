import assert from "node:assert/strict";
import { test } from "node:test";
import { createHash } from "node:crypto";
import { computeSmallFileHashes } from "../../../ui/small-file-hashes.js";
import { HASH_ALGORITHMS, resetHashDisplay, type HashAlgorithmControls } from "../../../ui/hash-controls.js";

const fixture = () => ({
  controls: HASH_ALGORITHMS.map(algorithm => ({ algorithm, label: algorithm.label,
    valueElement: { textContent: "" } as HTMLElement,
    buttonElement: { disabled: false, hidden: false, textContent: "Compute" } as HTMLButtonElement,
    copyButtonElement: { hidden: true } as HTMLButtonElement })) satisfies HashAlgorithmControls[],
  status: { textContent: "", dataset: {} } as HTMLElement
});

const digestName = (id: string): string => id.replace(/^sha512(224|256)$/, "sha512-$1");

for (const size of [0, 3, 65536]) {
  void test(`automatic hashes match independent digests and read the source once at ${size} bytes`, async () => {
    const state = fixture();
    const bytes = new Uint8Array(size).fill(37);
    const file = new File([bytes], "small.bin");
    const read = file.arrayBuffer.bind(file);
    let reads = 0;
    Object.defineProperty(file, "arrayBuffer", { value: () => { reads++; return read(); } });

    await computeSmallFileHashes(file, state.controls, () => true, state.status);

    assert.equal(reads, 1);
    assert.deepEqual(state.controls.map(control => control.valueElement.textContent),
      HASH_ALGORITHMS.map(algorithm => createHash(digestName(algorithm.id)).update(bytes).digest("hex")));
    assert.ok(state.controls.every(control => control.buttonElement.hidden && !control.copyButtonElement.hidden));
    assert.equal(state.status.textContent, "");
  });
}

for (const size of [65537, -1, NaN, Infinity, 0.5]) {
  void test(`automatic hashes skip ineligible size ${size} without reading or changing controls`, async () => {
    const state = fixture();
    const file = new File(["abc"], "sample");
    Object.defineProperty(file, "size", { value: size });
    Object.defineProperty(file, "arrayBuffer", { value: () => assert.fail("Must not read ineligible files") });

    await computeSmallFileHashes(file, state.controls, () => true, state.status);

    assert.ok(state.controls.every(control => !control.buttonElement.disabled && !control.valueElement.textContent));
    assert.ok(state.controls.every(control => control.buttonElement.textContent === "Compute"));
    assert.equal(state.status.textContent, "");
  });
}

void test("automatic hashing does not repeat completed work or compete with an active manual request", async () => {
  const state = fixture();
  state.controls[0]!.valueElement.textContent = "already computed";
  state.controls[1]!.buttonElement.disabled = true;
  const file = new File(["abc"], "sample");

  await computeSmallFileHashes(file, state.controls, () => true, state.status);

  assert.equal(state.controls[0]!.valueElement.textContent, "already computed");
  assert.equal(state.controls[1]!.valueElement.textContent, "");
  assert.equal(state.controls[3]!.valueElement.textContent, createHash("sha256").update("abc").digest("hex"));
  await computeSmallFileHashes(file, state.controls, () => true, state.status);
});

void test("a changed selection cannot overwrite the reset controls", async () => {
  const state = fixture();
  const file = new File(["abc"], "sample");
  let resolveRead: (value: ArrayBuffer) => void = () => {};
  Object.defineProperty(file, "arrayBuffer", { value: () => new Promise<ArrayBuffer>(resolve => {
    resolveRead = resolve;
  }) });
  let current = true;
  const computing = computeSmallFileHashes(file, state.controls, () => current, state.status);
  assert.ok(state.controls.every(control => control.buttonElement.disabled));
  assert.ok(state.controls.every(control => control.buttonElement.textContent === "Working..."));
  current = false;
  resetHashDisplay(...state.controls);

  resolveRead(new TextEncoder().encode("abc").buffer);
  await computing;

  assert.ok(state.controls.every(control => control.valueElement.textContent === "" && !control.buttonElement.disabled));
  assert.equal(state.status.textContent, "");
});

void test("a rejected stale read does not report an error on the next file", async () => {
  const state = fixture();
  const file = new File(["abc"], "sample");
  let current = true;
  Object.defineProperty(file, "arrayBuffer", { value: async () => { current = false; throw new Error("stale"); } });

  await computeSmallFileHashes(file, state.controls, () => current, state.status);

  assert.equal(state.status.textContent, "");
});

for (const failure of [new Error("read failed"), "read denied"]) {
  void test(`read failure ${String(failure)} remains visible and retryable`, async () => {
    const state = fixture();
    const file = new File(["abc"], "sample");
    Object.defineProperty(file, "arrayBuffer", { value: async () => { throw failure; } });

    await computeSmallFileHashes(file, state.controls, () => true, state.status);

    assert.match(state.status.textContent!, /Automatic hashes failed:/);
    assert.equal(state.status.dataset["state"], "failed");
    assert.ok(state.controls.every(control => !control.buttonElement.disabled && control.buttonElement.textContent === "Retry"));
  });
}

void test("incomplete reads fail explicitly and empty or stale requests do no work", async () => {
  const state = fixture();
  const file = new File(["abc"], "sample");
  Object.defineProperty(file, "arrayBuffer", { value: async () => new ArrayBuffer(2) });

  await computeSmallFileHashes(file, state.controls, () => true, state.status);

  assert.match(state.status.textContent!, /Incomplete file read/);
  state.status.textContent = "";
  await computeSmallFileHashes(file, [], () => true, state.status);
  await computeSmallFileHashes(file, state.controls, () => false, state.status);
  assert.equal(state.status.textContent, "");
});
