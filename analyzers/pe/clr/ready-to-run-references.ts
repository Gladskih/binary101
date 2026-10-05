import type { PeClrReadyToRunSection } from "./ready-to-run-types.js";
import { readyToRunRuntimeFunctionSize } from "./ready-to-run-target.js";

export const validateReadyToRunReferences = (
  sections: PeClrReadyToRunSection[], machine: number | undefined, issues: string[]
): void => {
  const functions = sections.find(section => section.type === 102);
  const width = readyToRunRuntimeFunctionSize(machine);
  if (!functions || !width) return;
  if (functions.size % width) issues.push("RuntimeFunctions ends with an incomplete entry.");
  const count = Math.floor(functions.size / width);
  const invalid = sections.some(section => {
    const decoded = section.decoded;
    if (decoded?.kind === "methods" || decoded?.kind === "instance-methods") {
      return decoded.methods.some(method => method.runtimeFunctionIndex >= count);
    }
    return decoded?.kind === "hot-cold" && decoded.entries.some(entry =>
      entry.hotRuntimeFunction >= count || entry.coldRuntimeFunction >= count);
  });
  if (invalid) issues.push("ReadyToRun method map references a missing runtime-function index.");
};
