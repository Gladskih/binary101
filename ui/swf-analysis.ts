import type { ParseForUiResult } from "../analyzers/analyzer-types.js";
import { isPeWindowsParseResult, type PeWindowsParseResult } from "../analyzers/pe/index.js";
import type { SwfBodyJob, SwfBodyResponse } from "./swf-worker-protocol.js";
import { resolveProjectorCandidate } from "../analyzers/pe/payloads.js";
import { subtractFileRanges } from "../analyzers/pe/layout/file-ranges.js";
import type { SwfParseResult } from "../analyzers/swf/types.js";

export type SwfBodyWorker = Pick<Worker, "postMessage" | "terminate" | "onmessage" | "onerror">;

const peBodyJobs = (file: File, pe: PeWindowsParseResult): SwfBodyJob[] => {
  const jobs = (pe.payloads?.entries ?? []).flatMap(payload => payload.format === "swf"
    ? [{ file, start: payload.start, end: payload.end, swf: payload.swf }] : []);
  if (pe.payloads?.projectorCandidate && !pe.payloads.projectorCandidate.bodyReadError) {
    jobs.push({ file, ...pe.payloads.projectorCandidate });
  }
  return jobs;
};

const pendingBodies = (file: File, result: ParseForUiResult): SwfBodyJob[] => {
  let jobs: SwfBodyJob[] = [];
  if (result.analyzer === "swf") jobs = [{ file, start: 0, end: file.size, swf: result.parsed }];
  else if (result.analyzer === "pe" && isPeWindowsParseResult(result.parsed)) jobs = peBodyJobs(file, result.parsed);
  return jobs.filter(job => job.swf.signature !== "FWS" && !job.swf.issues.length && job.swf.tags == null);
};

const publishProjector = (pe: PeWindowsParseResult, job: SwfBodyJob, swf: SwfParseResult): void => {
  pe.payloads = resolveProjectorCandidate(pe.payloads!, swf);
  if (pe.payloads.projectorCandidate || !pe.overlay) return;
  const findings = pe.overlay.ranges.flatMap(range => range.findings);
  const ranges = subtractFileRanges(pe.overlay.ranges, [{ start: job.start, end: job.end + 8 }])
    .map(range => ({ ...range, size: range.end - range.start,
      findings: findings.filter(finding => finding.start >= range.start && finding.end <= range.end) }));
  if (ranges.length || pe.overlay.warnings?.length) pe.overlay = { ...pe.overlay, ranges };
  else delete pe.overlay;
};

const attachAnalysis = (result: ParseForUiResult, job: SwfBodyJob, response: SwfBodyResponse): void => {
  if (!("analysis" in response)) { recordWorkerFailure(result, job, response.error); return; }
  if (result.analyzer === "pe" && isPeWindowsParseResult(result.parsed) &&
      result.parsed.payloads?.projectorCandidate?.swf === job.swf) {
    publishProjector(result.parsed, job, response.analysis);
  } else Object.assign(job.swf, response.analysis);
};

const recordWorkerFailure = (result: ParseForUiResult, job: SwfBodyJob, message: string): void => {
  if (result.analyzer === "pe" && isPeWindowsParseResult(result.parsed) &&
      result.parsed.payloads?.projectorCandidate?.swf === job.swf) {
    result.parsed.payloads.projectorCandidate.bodyReadError = message;
  } else job.swf.issues.push(message);
};

class SwfBodyAnalysisController {
  readonly #getFile: () => File | null;
  readonly #getParseResult: () => ParseForUiResult;
  readonly #renderResult: (result: ParseForUiResult) => void;
  readonly #createWorker: () => SwfBodyWorker;
  readonly #active = new Map<SwfBodyWorker, SwfBodyJob>();
  #attempted = new WeakSet<SwfBodyJob["swf"]>();

  constructor(getFile: () => File | null, getParseResult: () => ParseForUiResult,
    renderResult: (result: ParseForUiResult) => void, createWorker: () => SwfBodyWorker) {
    this.#getFile = getFile;
    this.#getParseResult = getParseResult;
    this.#renderResult = renderResult;
    this.#createWorker = createWorker;
  }

  #complete(worker: SwfBodyWorker, response: SwfBodyResponse): void {
    const job = this.#active.get(worker);
    if (!job) return;
    worker.terminate();
    this.#active.delete(worker);
    if (this.#getFile() !== job.file ||
        !pendingBodies(job.file, this.#getParseResult()).some(current => current.swf === job.swf)) return;
    attachAnalysis(this.#getParseResult(), job, response);
    this.#renderResult(this.#getParseResult());
  }

  #startJob(job: SwfBodyJob): void {
    this.#attempted.add(job.swf);
    let worker: SwfBodyWorker | undefined;
    try {
      const created = this.#createWorker();
      worker = created;
      this.#active.set(created, job);
      created.onmessage = (event: MessageEvent<SwfBodyResponse>) => this.#complete(created, event.data);
      created.onerror = event => this.#complete(created, { error: `SWF background analysis failed: ${event.message}` });
      created.postMessage(job);
    } catch (error) {
      worker?.terminate();
      if (worker) this.#active.delete(worker);
      recordWorkerFailure(this.#getParseResult(), job,
        error instanceof Error ? error.message : "SWF background worker could not start.");
      queueMicrotask(() => {
        if (this.#getFile() === job.file) this.#renderResult(this.#getParseResult());
      });
    }
  }

  start(): void {
    const file = this.#getFile();
    if (!file) return;
    for (const job of pendingBodies(file, this.#getParseResult())) {
      if (!this.#attempted.has(job.swf)) this.#startJob(job);
    }
  }

  cancel(): void {
    for (const worker of this.#active.keys()) worker.terminate();
    this.#active.clear();
    this.#attempted = new WeakSet();
  }
}

export const createSwfBodyAnalysis = (
  getFile: () => File | null,
  getParseResult: () => ParseForUiResult,
  renderResult: (result: ParseForUiResult) => void,
  createWorker: () => SwfBodyWorker = () =>
    new Worker(new URL("./swf-body-worker.ts", import.meta.url), { type: "module" })
) => new SwfBodyAnalysisController(getFile, getParseResult, renderResult, createWorker);
