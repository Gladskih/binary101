"use strict";

import { open, type FileHandle } from "node:fs/promises";
import type { Worker } from "node:worker_threads";
import type { NativeAotDiskScanResult } from "./analysis.js";

export type WorkerResponse = { error?: string; result?: NativeAotDiskScanResult };

type WorkerReadRequest = {
  kind: "read";
  jobId: number;
  requestId: number;
  offset: number;
  byteLength: number;
};
type WorkerResult = { kind: "result"; jobId: number } & WorkerResponse;
type WorkerMessage = WorkerReadRequest | WorkerResult;
type ActiveJob = {
  handle: FileHandle;
  resolve: (response: WorkerResponse) => void;
  sizeBytes: number;
  timeout: ReturnType<typeof setTimeout>;
  worker: Worker;
};

export class ScanCoordinator {
  readonly #activeJobs = new Map<number, ActiveJob>();
  readonly #failedWorkers = new WeakMap<Worker, string>();
  #nextJobId = 1;
  constructor(private readonly timeoutMs: number) {}
  attach(worker: Worker): void {
    worker.on("message", (message: WorkerMessage) => {
      if (message.kind === "read") {
        void this.#read(worker, message).catch(error => this.#failWorker(worker, String(error)));
      } else void this.#finish(worker, message);
    });
    worker.on("error", (error: Error) => this.#failWorker(worker, error.message));
    worker.on("exit", code => this.#failWorker(worker, `Worker exited with code ${code}.`));
  }
  async scan(worker: Worker, path: string): Promise<WorkerResponse> {
    let handle: FileHandle | null = null;
    try {
      if (this.#failedWorkers.has(worker)) return { error: this.#failedWorkers.get(worker)! };
      handle = await open(path, "r");
      const info = await handle.stat();
      if (!info.isFile() || info.size < 2) {
        await handle.close();
        return { result: { match: null, pe: false } };
      }
      if (this.#failedWorkers.has(worker)) {
        await handle.close();
        return { error: this.#failedWorkers.get(worker)! };
      }
      const jobId = this.#nextJobId++;
      return await new Promise<WorkerResponse>(resolve => {
        const timeout = setTimeout(() => this.#cancel(jobId), this.timeoutMs);
        this.#activeJobs.set(jobId, {
          handle: handle as FileHandle,
          resolve,
          sizeBytes: info.size,
          timeout,
          worker
        });
        try {
          worker.postMessage({ kind: "scan", jobId, path, sizeBytes: info.size });
        } catch (error) {
          this.#failWorker(worker, String(error));
        }
      });
    } catch (error) {
      if (handle) await handle.close().catch(() => undefined);
      return { error: error instanceof Error ? error.message : String(error) };
    }
  }
  async #read(worker: Worker, request: WorkerReadRequest): Promise<void> {
    const job = this.#activeJobs.get(request.jobId);
    if (!job || job.worker !== worker) {
      worker.postMessage({
        kind: "read-response",
        jobId: request.jobId,
        requestId: request.requestId,
        error: "Analysis job is no longer active."
      });
      return;
    }
    try {
      const available = this.#availableBytes(job.sizeBytes, request.offset, request.byteLength);
      const bytes = new Uint8Array(available);
      const result = await job.handle.read(bytes, 0, available, request.offset);
      const data = result.bytesRead === bytes.byteLength ? bytes.buffer : bytes.slice(0, result.bytesRead).buffer;
      worker.postMessage({
        kind: "read-response",
        jobId: request.jobId,
        requestId: request.requestId,
        data
      }, [data]);
    } catch (error) {
      worker.postMessage({
        kind: "read-response",
        jobId: request.jobId,
        requestId: request.requestId,
        error: error instanceof Error ? error.message : String(error)
      });
    }
  }
  async #finish(worker: Worker, message: WorkerResult): Promise<void> {
    const job = this.#activeJobs.get(message.jobId);
    if (!job || job.worker !== worker) return;
    this.#activeJobs.delete(message.jobId);
    clearTimeout(job.timeout);
    await job.handle.close().catch(() => undefined);
    job.resolve(message.error
      ? { error: message.error }
      : message.result
        ? { result: message.result }
        : { error: "Worker returned no result." });
  }
  #cancel(jobId: number): void {
    const job = this.#activeJobs.get(jobId);
    if (!job) return;
    this.#activeJobs.delete(jobId);
    try {
      job.worker.postMessage({ kind: "cancel", jobId });
    } catch (error) {
      this.#failWorker(job.worker, String(error));
    }
    void job.handle.close().catch(() => undefined);
    job.resolve({ error: `Analysis exceeded ${this.timeoutMs} ms.` });
  }
  #failWorker(worker: Worker, error: string): void {
    this.#failedWorkers.set(worker, error);
    for (const [jobId, job] of this.#activeJobs) {
      if (job.worker !== worker) continue;
      void this.#finish(worker, { kind: "result", jobId, error });
    }
  }
  #availableBytes(fileSize: number, offset: number, byteLength: number): number {
    if (!Number.isSafeInteger(offset) || !Number.isSafeInteger(byteLength)) return 0;
    if (offset < 0 || byteLength < 1 || offset >= fileSize) return 0;
    return Math.min(byteLength, fileSize - offset);
  }
}
