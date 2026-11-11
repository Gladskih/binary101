import { parseWebm } from "../analyzers/webm/index.js";
import type { WebmWorkerResponse } from "./webm-worker-protocol.js";

const send = (message: WebmWorkerResponse): void => self.postMessage(message);

self.onmessage = async (event: MessageEvent<File>): Promise<void> => {
  let reported = -1;
  try {
    send({ type: "result", result: await parseWebm(event.data, {
      signal: new AbortController().signal,
      onProgress: (position, total) => {
        const percent = Math.floor(position / total * 100);
        if (percent === reported) return;
        reported = percent;
        send({ type: "progress", position, total });
      }
    }) });
  } catch (error) {
    send({ type: "error", message: error instanceof Error ? error.message : String(error) });
  }
};
