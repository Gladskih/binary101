import assert from "node:assert/strict";
import { EventEmitter, once } from "node:events";
import { test } from "node:test";
import type { Worker } from "node:worker_threads";
import { ScanCoordinator } from "../../../../scripts/native-aot-disk-scan/coordinator.js";

class TestWorker extends EventEmitter {
  postMessage(message: unknown): void { this.emit("posted", message); }
}

void test("coordinator resolves pending and future scans when a worker exits", async () => {
  const worker = new TestWorker();
  const coordinator = new ScanCoordinator(100);
  coordinator.attach(worker as unknown as Worker);
  const posted = once(worker, "posted");
  const response = coordinator.scan(worker as unknown as Worker, "package.json");
  await posted;

  worker.emit("exit", 1);

  assert.match((await response).error ?? "", /exited/);
  assert.match((await coordinator.scan(worker as unknown as Worker, "package.json")).error ?? "",
    /exited/);
});

void test("coordinator ignores results from a different worker", async () => {
  const worker = new TestWorker();
  const stranger = new TestWorker();
  const coordinator = new ScanCoordinator(100);
  coordinator.attach(worker as unknown as Worker);
  coordinator.attach(stranger as unknown as Worker);
  const posted = once(worker, "posted");
  const response = coordinator.scan(worker as unknown as Worker, "package.json");
  const [request] = await posted as [{ jobId: number }];

  stranger.emit("message", { kind: "result", jobId: request.jobId,
    result: { match: null, pe: true } });
  worker.emit("message", { kind: "result", jobId: request.jobId,
    result: { match: null, pe: false } });

  assert.deepEqual((await response).result, { match: null, pe: false });
});
