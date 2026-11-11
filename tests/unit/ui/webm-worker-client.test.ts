import assert from "node:assert/strict";
import { test } from "node:test";
import { parseWebmInWorker } from "../../../ui/webm-worker-client.js";
import type { WebmWorker, WebmWorkerResponse } from "../../../ui/webm-worker-protocol.js";

class TestWorker implements WebmWorker {
  onmessage: WebmWorker["onmessage"] = null;
  onmessageerror: WebmWorker["onmessageerror"] = null;
  onerror: WebmWorker["onerror"] = null;
  sent: File | null = null;
  terminated = 0;
  postMessage(file: File): void { this.sent = file; }
  terminate(): void { this.terminated++; }
  emit(message: WebmWorkerResponse): void {
    this.onmessage?.({ data: message } as MessageEvent<WebmWorkerResponse>);
  }
}
const file = new File([], "media.mkv");

void test("worker parser forwards the File, progress and result and releases its worker", async () => {
  const worker = new TestWorker();
  const progress: number[][] = [];
  const pending = parseWebmInWorker(file, new AbortController().signal,
    (position, total) => progress.push([position, total]), () => worker);

  worker.emit({ type: "progress", position: 1, total: 2 });
  assert.equal(worker.terminated, 0);
  worker.emit({ type: "result", result: null });

  assert.equal(await pending, null);
  assert.equal(worker.sent, file);
  assert.deepEqual(progress, [[1, 2]]);
  assert.equal(worker.terminated, 1);
  assert.equal(worker.onmessage, null);
});

void test("worker parser reports analyzer errors", async () => {
  const worker = new TestWorker();
  const pending = parseWebmInWorker(file, new AbortController().signal, () => undefined, () => worker);

  worker.emit({ type: "error", message: "read failed" });

  await assert.rejects(pending, /read failed/);
  assert.equal(worker.terminated, 1);
});

void test("worker parser terminates pending work when selection changes", async () => {
  const worker = new TestWorker();
  const controller = new AbortController();
  const pending = parseWebmInWorker(file, controller.signal, () => undefined, () => worker);

  controller.abort();
  worker.emit({ type: "result", result: null });

  await assert.rejects(pending, { name: "AbortError" });
  assert.equal(worker.terminated, 1);
});

void test("worker parser does not create a worker for an already cancelled job", async () => {
  const controller = new AbortController();
  controller.abort();

  await assert.rejects(parseWebmInWorker(file, controller.signal, () => undefined,
    () => assert.fail("Cancelled job must not start")), { name: "AbortError" });
});

void test("worker parser handles cancellation while constructing the worker", async () => {
  const worker = new TestWorker();
  const controller = new AbortController();

  await assert.rejects(parseWebmInWorker(file, controller.signal, () => undefined,
    () => { controller.abort(); return worker; }), { name: "AbortError" });
  assert.equal(worker.sent, null);
  assert.equal(worker.terminated, 1);
});

void test("worker parser exposes start and serialization failures", async () => {
  const worker = new TestWorker();
  worker.postMessage = () => { throw new Error("clone failed"); };

  await assert.rejects(parseWebmInWorker(file, new AbortController().signal, () => undefined,
    () => worker), /clone failed/);
  await assert.rejects(parseWebmInWorker(file, new AbortController().signal, () => undefined,
    () => { throw new Error("worker blocked"); }), /worker blocked/);
  assert.equal(worker.terminated, 1);
});

void test("worker parser reports loading errors without uncaught browser events", async () => {
  const worker = new TestWorker();
  let prevented = 0;
  const pending = parseWebmInWorker(file, new AbortController().signal, () => undefined, () => worker);

  worker.onerror?.({ message: "load failed", preventDefault: () => { prevented++; } } as ErrorEvent);

  await assert.rejects(pending, /load failed/);
  assert.equal(worker.terminated, 1);
  assert.equal(prevented, 1);
});

void test("worker parser reports message decoding failures", async () => {
  const worker = new TestWorker();
  const pending = parseWebmInWorker(file, new AbortController().signal, () => undefined, () => worker);

  worker.onmessageerror?.({} as MessageEvent);

  await assert.rejects(pending, /could not be decoded/);
  assert.equal(worker.terminated, 1);
});

void test("worker parser rejects a failed progress consumer instead of leaving work pending", async () => {
  const worker = new TestWorker();
  const pending = parseWebmInWorker(file, new AbortController().signal,
    () => { throw new Error("progress failed"); }, () => worker);

  worker.emit({ type: "progress", position: 1, total: 2 });

  await assert.rejects(pending, /progress failed/);
  assert.equal(worker.terminated, 1);
});
