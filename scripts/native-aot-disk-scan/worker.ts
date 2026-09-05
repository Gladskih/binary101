"use strict";

import { basename } from "node:path";
import { parentPort } from "node:worker_threads";
import { createFileRangeReader } from "../../analyzers/file-range-reader.js";
import { scanNativeAotReader } from "./analysis.js";

type ScanRequest = { kind: "scan"; jobId: number; path: string; sizeBytes: number };
type CancelRequest = { kind: "cancel"; jobId: number };
type ReadResponse = {
  kind: "read-response";
  jobId: number;
  requestId: number;
  data?: ArrayBuffer;
  error?: string;
};
type WorkerRequest = CancelRequest | ScanRequest | ReadResponse;
type ReadWaiter = {
  jobId: number;
  reject: (error: Error) => void;
  resolve: (data: ArrayBuffer) => void;
};

const readWaiters = new Map<number, ReadWaiter>();
let nextRequestId = 1;

const requestRange = async (
  jobId: number,
  offset: number,
  byteLength: number
): Promise<ArrayBuffer> => {
  const requestId = nextRequestId++;
  const result = new Promise<ArrayBuffer>((resolve, reject) => {
    readWaiters.set(requestId, { jobId, reject, resolve });
  });
  parentPort?.postMessage({ kind: "read", jobId, requestId, offset, byteLength });
  return result;
};

const cancelJob = (jobId: number): void => {
  for (const [requestId, waiter] of readWaiters) {
    if (waiter.jobId !== jobId) continue;
    readWaiters.delete(requestId);
    waiter.reject(new Error("Analysis job was cancelled."));
  }
};

const createRemoteFile = (request: ScanRequest): File => ({
  name: basename(request.path),
  size: request.sizeBytes,
  slice(start = 0, end = request.sizeBytes) {
    const offset = Math.max(0, Math.min(Math.floor(start), request.sizeBytes));
    const limit = Math.max(offset, Math.min(Math.floor(end), request.sizeBytes));
    return { arrayBuffer: () => requestRange(request.jobId, offset, limit - offset) };
  }
} as File);

const runScan = async (request: ScanRequest): Promise<void> => {
  try {
    const reader = createFileRangeReader(createRemoteFile(request), 0, request.sizeBytes);
    const result = await scanNativeAotReader(reader, request.path, request.sizeBytes);
    parentPort?.postMessage({ kind: "result", jobId: request.jobId, result });
  } catch (error) {
    parentPort?.postMessage({
      kind: "result",
      jobId: request.jobId,
      error: error instanceof Error ? error.message : String(error)
    });
  }
};

const resolveRead = (response: ReadResponse): void => {
  const waiter = readWaiters.get(response.requestId);
  if (!waiter) return;
  readWaiters.delete(response.requestId);
  if (response.error) waiter.reject(new Error(response.error));
  else waiter.resolve(response.data ?? new ArrayBuffer(0));
};

parentPort?.on("message", (request: WorkerRequest) => {
  if (request.kind === "scan") void runScan(request);
  else if (request.kind === "cancel") cancelJob(request.jobId);
  else resolveRead(request);
});

parentPort?.postMessage({ kind: "ready" });
