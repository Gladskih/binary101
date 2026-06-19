"use strict";

import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { test } from "node:test";
import { HASH_ALGORITHMS, computeAndDisplayHash, type HashControls } from "../../../ui/hash-controls.js";

const createHashControlsFixture = (): {
  controls: HashControls;
  valueElement: HTMLElement;
} => {
  const valueElement = { textContent: "" } as HTMLElement;
  return {
    controls: {
      label: "MD5",
      valueElement,
      buttonElement: { hidden: false, disabled: false, textContent: "Compute MD5" } as HTMLButtonElement,
      copyButtonElement: { hidden: true } as HTMLButtonElement
    },
    valueElement
  };
};

const getMd5Algorithm = () => {
  const algorithm = HASH_ALGORITHMS.find(entry => entry.id === "md5");
  assert.ok(algorithm);
  return algorithm;
};

const installFallbackWorkerStub = (digest: ArrayBuffer): {
  restore: () => void;
  workerCount: () => number;
} => {
  const globals = globalThis as unknown as Record<string, unknown>;
  const workerDescriptor = Object.getOwnPropertyDescriptor(globals, "Worker");
  let count = 0;
  const FakeWorker = class {
    messageListener: ((event: MessageEvent<unknown>) => void) | undefined;

    constructor() { count += 1; }

    addEventListener(type: string, listener: (event: MessageEvent<unknown>) => void): void {
      if (type === "message") this.messageListener = listener;
    }

    postMessage(): void {
      this.messageListener?.({ data: { digest } } as MessageEvent<unknown>);
    }

    terminate(): void {}
  };
  Object.defineProperty(globals, "Worker", { configurable: true, value: FakeWorker });
  return {
    restore: () => {
      if (workerDescriptor) {
        Object.defineProperty(globals, "Worker", workerDescriptor);
        return;
      }
      Reflect.deleteProperty(globals, "Worker");
    },
    workerCount: () => count
  };
};

void test("computeAndDisplayHash sends browser fallback work to a worker", async () => {
  const fileBytes = new TextEncoder().encode("abc");
  const expected = createHash("md5").update(fileBytes).digest();
  const worker = installFallbackWorkerStub(expected.buffer.slice(0));
  const { controls, valueElement } = createHashControlsFixture();

  try {
    await computeAndDisplayHash(getMd5Algorithm(), new File([fileBytes], "abc.bin"), controls);
    assert.equal(valueElement.textContent, expected.toString("hex"));
    assert.equal(worker.workerCount(), 1);
  } finally {
    worker.restore();
  }
});
