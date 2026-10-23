import type { PeDebugDirectoryEntry } from "../../analyzers/pe/debug/directory.js";
import { escapeHtmlText, renderDefinitionRow } from "../../html-utils.js";

export const renderSpgoDebug = (entry: PeDebugDirectoryEntry, out: string[]): void => {
  if (!entry.spgo) return;
  out.push(`<dl>${renderDefinitionRow("SPGO text", escapeHtmlText(entry.spgo.text || "(empty)"),
    "NUL-terminated UTF-16 text. The public layout does not establish the meaning of this string.")}</dl>`);
};
