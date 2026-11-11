import { createParseForUi } from "../analyzers/parse-for-ui.js";
import { parseWebmInWorker } from "./webm-worker-client.js";
import type { ParseForUiResult } from "../analyzers/analyzer-types.js";

export const createInspectionFileParser = (
  progress: Pick<HTMLElement, "hidden">,
  bar: Pick<HTMLProgressElement, "value" | "hasAttribute" | "removeAttribute">,
  percentLabel: Pick<HTMLElement, "textContent">,
  clearStatus: () => void,
  parseWebmFile = parseWebmInWorker
) => {
  let active: AbortController | null = null;
  const finish = (): void => { active = null; progress.hidden = true; };
  const parse = (file: File): Promise<ParseForUiResult> => {
    const controller = new AbortController();
    active = controller;
    return createParseForUi(undefined, ebmlFile => {
      controller.signal.throwIfAborted();
      clearStatus();
      bar.removeAttribute("value");
      percentLabel.textContent = "";
      progress.hidden = false;
      return parseWebmFile(ebmlFile, controller.signal, (position, total) => {
          const percent = Math.floor(position / total * 100);
          if (bar.value === percent && bar.hasAttribute("value")) return;
          bar.value = percent;
          percentLabel.textContent = `${percent}%`;
      });
    })(file);
  };
  return { parse, finish, cancel: (): void => { active?.abort(); finish(); } };
};
