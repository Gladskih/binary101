"use strict";

import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { test } from "node:test";
import {
  attachHashWorkerListener,
  handleHashWorkerMessage
} from "../../../ui/hash-fallback-worker.js";

void test("handleHashWorkerMessage computes fallback digests", async () => {
  const bytes = new TextEncoder().encode("abc");
  const response = await handleHashWorkerMessage({
    algorithmId: "sha224",
    file: new File([bytes], "abc.bin")
  });

  assert.ok("digest" in response);
  assert.equal(
    Buffer.from(response.digest).toString("hex"),
    createHash("sha224").update(bytes).digest("hex")
  );
});

void test("handleHashWorkerMessage rejects malformed requests", async () => {
  const response = await handleHashWorkerMessage({ algorithmId: "sha256" });

  assert.deepEqual(response, { error: "Invalid fallback hash request." });
});

void test("handleHashWorkerMessage reports file reading failures", async () => {
  const file = new File(["abc"], "abc.bin");
  Object.defineProperty(file, "stream", {
    value: () => ({
      getReader: () => ({
        read: async () => { throw new Error("boom"); },
        releaseLock: () => undefined
      })
    })
  });
  const response = await handleHashWorkerMessage({ algorithmId: "md5", file });

  assert.deepEqual(response, { error: "Error: boom" });
});

void test("attachHashWorkerListener posts the computed response", async () => {
  let listener: ((event: MessageEvent<unknown>) => void) | undefined;
  let resolveResponse: (response: unknown) => void = () => undefined;
  const response = new Promise<unknown>(resolve => { resolveResponse = resolve; });

  attachHashWorkerListener({
    addEventListener: (_, nextListener) => { listener = nextListener; },
    postMessage: resolveResponse
  });
  assert.ok(listener);
  listener({
    data: { algorithmId: "md5", file: new File(["abc"], "abc.bin") }
  } as MessageEvent<unknown>);

  const result = await response;
  assert.ok(result && typeof result === "object" && "digest" in result);
});
