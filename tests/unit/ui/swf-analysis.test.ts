import assert from "node:assert/strict";
import { test } from "node:test";
import { createSwfBodyAnalysis, type SwfBodyWorker } from "../../../ui/swf-analysis.js";
import type { SwfBodyJob, SwfBodyResponse } from "../../../ui/swf-worker-protocol.js";
import type { ParseForUiResult } from "../../../analyzers/analyzer-types.js";
import { parsePe, isPeWindowsParseResult } from "../../../analyzers/pe/index.js";
import type { SwfParseResult } from "../../../analyzers/swf/types.js";
import { MockFile } from "../../helpers/mock-file.js";
import { createPePlusFile } from "../../fixtures/sample-files-pe.js";

class WorkerFailureEvent extends Event implements ErrorEvent {
  readonly colno = 0;
  readonly lineno = 0;
  readonly filename = "";
  readonly error: unknown = null;
  constructor(readonly message: string) { super("error"); }
}

class RecordingWorker implements SwfBodyWorker {
  onmessage: ((event: MessageEvent<SwfBodyResponse>) => void) | null = null;
  onerror: ((event: ErrorEvent) => void) | null = null;
  jobs: SwfBodyJob[] = [];
  terminated = 0;
  postMessage(job: SwfBodyJob): void { this.jobs.push(job); }
  terminate(): void { this.terminated++; }
  respond(response: SwfBodyResponse): void {
    this.onmessage?.(new MessageEvent("message", { data: response }));
  }
  fail(message: string): void {
    this.onerror?.(new WorkerFailureEvent(message));
  }
}

const compressed = (): SwfParseResult => ({ signature: "CWS", version: 9, fileLength: 32, issues: [] });

const parsedPe = async () => {
  const pe = await parsePe(createPePlusFile());
  assert.ok(pe && isPeWindowsParseResult(pe));
  return pe;
};

const standalone = () => {
  const file = new MockFile(new Uint8Array(32));
  const parsed = compressed();
  const result: ParseForUiResult = { analyzer: "swf", parsed };
  return { file, parsed, result };
};

void test("SWF body analysis starts automatically once and persists its findings before any panel is opened", () => {
  const fixture = standalone();
  const worker = new RecordingWorker();
  const renders: ParseForUiResult[] = [];
  const controller = createSwfBodyAnalysis(() => fixture.file, () => fixture.result,
    result => renders.push(result), () => worker);

  controller.start();
  controller.start();
  worker.respond({ analysis: { ...compressed(), tags: [{ code: 82, count: 2, bodyBytes: 100 }] } });
  controller.start();

  assert.equal(worker.jobs.length, 1);
  assert.equal(worker.jobs[0]?.start, 0);
  assert.equal(worker.jobs[0]?.end, fixture.file.size);
  assert.equal(fixture.parsed.tags?.[0]?.count, 2);
  assert.deepEqual(renders, [fixture.result]);
  assert.equal(worker.terminated, 1);
});

void test("PE SWF background analysis uses its exact payload interval, independent of disclosure state", async () => {
  const file = new MockFile(new Uint8Array(256));
  const swf = compressed();
  const pe = await parsedPe();
  pe.payloads = {
    entries: [{ start: 128, end: 200, format: "swf", swf, provenance: { location: "overlay",
      discovery: "projector-footer", association: "flash-projector", validation: "projector-footer" } }]
  };
  const result: ParseForUiResult = { analyzer: "pe", parsed: pe };
  const worker = new RecordingWorker();
  const controller = createSwfBodyAnalysis(() => file, () => result, () => undefined, () => worker);

  controller.start();

  assert.equal(worker.jobs[0]?.start, 128);
  assert.equal(worker.jobs[0]?.end, 200);
  controller.cancel();
  assert.equal(worker.terminated, 1);
});

void test("a verified background Projector candidate is published and its exact interval is removed from overlay", async () => {
  const file = new MockFile(new Uint8Array(256));
  const swf = compressed();
  const pe = await parsedPe();
  pe.payloads = { entries: [], projectorCandidate: { start: 128, end: 248, swf } };
  pe.overlay = { ranges: [{ start: 64, end: 256, size: 192, findings: [] }] };
  const result: ParseForUiResult = { analyzer: "pe", parsed: pe };
  const worker = new RecordingWorker();
  const controller = createSwfBodyAnalysis(() => file, () => result, () => undefined, () => worker);

  controller.start();
  worker.respond({ analysis: { ...compressed(), tagEnd: 32, tags: [], movie: {
    xMin: 0, xMax: 12800, yMin: 0, yMax: 9600, frameRate: 7680, frameCount: 1 } } });

  assert.equal(pe.payloads?.entries[0]?.format, "swf");
  assert.equal(pe.payloads?.projectorCandidate, undefined);
  assert.deepEqual(pe.overlay?.ranges, [{ start: 64, end: 128, size: 64, findings: [] }]);
});

void test("candidate worker infrastructure failures stay visible without publishing an unconfirmed SWF", async () => {
  const file = new MockFile(new Uint8Array(256));
  const candidate = { start: 128, end: 248, swf: compressed() };
  const pe = await parsedPe();
  pe.payloads = { entries: [], projectorCandidate: candidate };
  const worker = new RecordingWorker();
  const controller = createSwfBodyAnalysis(() => file, () => ({ analyzer: "pe", parsed: pe }),
    () => undefined, () => worker);

  controller.start();
  worker.fail("worker unavailable");
  controller.start();

  assert.equal(pe.payloads?.projectorCandidate?.bodyReadError?.includes("worker unavailable"), true);
  assert.deepEqual(pe.payloads?.entries, []);
  assert.equal(worker.jobs.length, 1);
});

void test("cancellation prevents late results and permits restarting the same pending model", () => {
  const fixture = standalone();
  const workers: RecordingWorker[] = [];
  let renders = 0;
  const controller = createSwfBodyAnalysis(() => fixture.file, () => fixture.result, () => renders++, () => {
    const worker = new RecordingWorker();
    workers.push(worker);
    return worker;
  });

  controller.start();
  controller.cancel();
  workers[0]!.respond({ analysis: { ...compressed(), tags: [] } });
  controller.start();

  assert.equal(fixture.parsed.tags, undefined);
  assert.equal(renders, 0);
  assert.equal(workers.length, 2);
  controller.cancel();
});

void test("file replacement prevents stale SWF worker findings from reaching the current view", () => {
  const fixture = standalone();
  let currentFile: File = fixture.file;
  const worker = new RecordingWorker();
  let renders = 0;
  const controller = createSwfBodyAnalysis(() => currentFile, () => fixture.result, () => renders++, () => worker);

  controller.start();
  currentFile = new MockFile(new Uint8Array(32));
  worker.respond({ analysis: { ...compressed(), tags: [] } });

  assert.equal(renders, 0);
  assert.equal(fixture.parsed.tags, undefined);
});

void test("SWF worker errors become visible findings without repeated automatic retries", () => {
  const fixture = standalone();
  const worker = new RecordingWorker();
  let renders = 0;
  const controller = createSwfBodyAnalysis(() => fixture.file, () => fixture.result, () => renders++, () => worker);

  controller.start();
  worker.fail("decoder unavailable");
  controller.start();

  assert.match(fixture.parsed.issues.join(), /decoder unavailable/);
  assert.equal(renders, 1);
  assert.equal(worker.jobs.length, 1);
});

void test("worker startup failures are surfaced without blocking the initial result", async () => {
  const fixture = standalone();
  let renders = 0;
  const controller = createSwfBodyAnalysis(() => fixture.file, () => fixture.result, () => renders++,
    () => { throw new Error("worker unavailable"); });

  controller.start();
  await Promise.resolve();

  assert.match(fixture.parsed.issues.join(), /worker unavailable/);
  assert.equal(renders, 1);
});

void test("postMessage failures terminate the worker and preserve an explicit analysis error", async () => {
  const fixture = standalone();
  const worker = new RecordingWorker();
  worker.postMessage = () => { throw new Error("file could not be cloned"); };
  const controller = createSwfBodyAnalysis(() => fixture.file, () => fixture.result, () => undefined, () => worker);

  controller.start();
  await Promise.resolve();

  assert.match(fixture.parsed.issues.join(), /file could not be cloned/);
  assert.equal(worker.terminated, 1);
});

void test("completed, malformed, uncompressed and unrelated results do not launch SWF workers", () => {
  const file = new MockFile(new Uint8Array(32));
  let calls = 0;
  const factory = (): SwfBodyWorker => { calls++; return new RecordingWorker(); };
  createSwfBodyAnalysis(() => null, () => ({ analyzer: null, parsed: null }), () => undefined, factory).start();
  createSwfBodyAnalysis(() => file, () => ({ analyzer: null, parsed: null }), () => undefined, factory).start();
  createSwfBodyAnalysis(() => file, () => ({ analyzer: "swf", parsed: { ...compressed(), tags: [] } }),
    () => undefined, factory).start();
  createSwfBodyAnalysis(() => file, () => ({ analyzer: "swf", parsed: { ...compressed(), issues: ["bad"] } }),
    () => undefined, factory).start();
  createSwfBodyAnalysis(() => file, () => ({ analyzer: "swf", parsed: { ...compressed(), signature: "FWS" } }),
    () => undefined, factory).start();

  assert.equal(calls, 0);
});
