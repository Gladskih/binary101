import assert from "node:assert/strict";
import { test } from "node:test";
import { parseWebm } from "../../../analyzers/webm/index.js";
import { createWebmWithDurationMismatch } from "../../fixtures/webm-duration-fixtures.js";
import type { WebmWorkerResponse } from "../../../ui/webm-worker-protocol.js";

void test("worker entry reports bounded progress and the unchanged parser result", async context => {
  const responses: WebmWorkerResponse[] = [];
  const scope: { postMessage: (message: WebmWorkerResponse) => void;
    onmessage?: (event: MessageEvent<File>) => Promise<void> } = {
    postMessage: message => responses.push(message)
  };
  Object.defineProperty(globalThis, "self", { value: scope, configurable: true });
  context.after(() => { Reflect.deleteProperty(globalThis, "self"); });
  await import("../../../ui/webm-worker.js");
  const file = createWebmWithDurationMismatch();

  await scope.onmessage!(new MessageEvent<File>("message", { data: file }));

  assert.deepEqual(responses.at(-1), { type: "result", result: await parseWebm(file) });
  assert.ok(responses.some(message => message.type === "progress"));
  responses.length = 0;
  file.slice = () => { throw new Error("fixture read failed"); };
  await scope.onmessage!(new MessageEvent<File>("message", { data: file }));
  assert.deepEqual(responses.at(-1), { type: "error", message: "fixture read failed" });
});
