import { escapeHtml } from "../html-utils.js";

export const renderInstructionSetAction = (
  id: string,
  report?: { bytesSampled: number }
): string => `<button type="button" class="actionButton" id="${escapeHtml(id)}"` +
  (report ? ` disabled>${report.bytesSampled ? "Instruction sets analyzed" : "No code to analyze"}` :
    ">Analyze instruction sets") + "</button>";
