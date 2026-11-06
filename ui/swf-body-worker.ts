import { analyzeSwfBody } from "../analyzers/swf/index.js";
import type { SwfBodyJob, SwfBodyResponse } from "./swf-worker-protocol.js";

const sendResult = (response: SwfBodyResponse): void => self.postMessage(response);

self.onmessage = async (event: MessageEvent<SwfBodyJob>): Promise<void> => {
  const job = event.data;
  try {
    sendResult({ analysis: await analyzeSwfBody(job.file, job.start, job.end, job.swf) });
  } catch (error) {
    sendResult({ error: error instanceof Error ? error.message : "SWF body analysis failed." });
  }
};
