import type { WebmParseResult } from "../analyzers/webm/types.js";
import type { WebmWorker } from "./webm-worker-protocol.js";

const readWorker = (
  worker: WebmWorker,
  file: File,
  signal: AbortSignal,
  onProgress: (position: number, total: number) => void
): Promise<WebmParseResult | null> => new Promise((resolve, reject) => {
  const clean = (): void => {
    signal.removeEventListener("abort", abort);
    worker.onmessage = worker.onmessageerror = worker.onerror = null;
    worker.terminate();
  };
  const fail = (reason: unknown): void => { clean(); reject(reason); };
  const abort = (): void => fail(signal.reason);
  worker.onmessage = event => {
    try {
      const message = event.data;
      if (message.type === "progress") {
        onProgress(message.position, message.total);
        return;
      }
      clean();
      if (message.type === "result") resolve(message.result);
      else reject(new Error(message.message));
    } catch (error) { fail(error); }
  };
  worker.onerror = event => {
    event.preventDefault();
    fail(new Error(event.message || "Matroska/WebM worker failed."));
  };
  worker.onmessageerror = () => fail(new Error("Matroska/WebM worker result could not be decoded."));
  signal.addEventListener("abort", abort, { once: true });
  if (signal.aborted) { abort(); return; }
  try { worker.postMessage(file); } catch (error) { fail(error); }
});

export const parseWebmInWorker = async (
  file: File,
  signal: AbortSignal,
  onProgress: (position: number, total: number) => void,
  createWorker: () => WebmWorker = () =>
    new Worker(new URL("./webm-worker.ts", import.meta.url), { type: "module" })
): Promise<WebmParseResult | null> => {
  signal.throwIfAborted();
  // File is structured-cloned, not read into a whole-file ArrayBuffer.
  // https://html.spec.whatwg.org/multipage/workers.html#dom-worker-terminate
  return readWorker(createWorker(), file, signal, onProgress);
};
