import type { WebmParseResult } from "../analyzers/webm/types.js";

export type WebmWorkerResponse =
  | { type: "progress"; position: number; total: number }
  | { type: "result"; result: WebmParseResult | null }
  | { type: "error"; message: string };

export interface WebmWorker {
  onmessage: ((event: MessageEvent<WebmWorkerResponse>) => void) | null;
  onmessageerror: ((event: MessageEvent) => void) | null;
  onerror: ((event: ErrorEvent) => void) | null;
  postMessage(file: File): void;
  terminate(): void;
}
