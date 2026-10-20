import type { PeDebugDirectoryEntry } from "../../analyzers/pe/debug/directory.js";
import { IMAGE_DEBUG_TYPE_OMAP_TO_SRC } from "../../analyzers/pe/debug/types.js";
import { humanSize } from "../../binary-utils.js";
import { renderDefinitionRow } from "../../html-utils.js";

export const renderOmap = (
  entry: PeDebugDirectoryEntry, _entryIndex: number, out: string[]
): void => {
  if (!entry.omap) return;
  const records = entry.omap.records;
  const ordered = records.every((record, index) => index === 0 || record.rva > records[index - 1]!.rva);
  const mapped = records.filter(record => record.rvaTo !== 0);
  const spanBytes = records.reduce((sum, record, index) => {
    const next = records[index + 1];
    return sum + (record.rvaTo !== 0 && next ? next.rva - record.rva : 0);
  }, 0);
  // OMAP: each record starts a region; the final region has no stored end.
  // https://learn.microsoft.com/en-us/windows/win32/api/dbghelp/ns-dbghelp-omap
  out.push(`<p class="smallNote">Source means the original image layout before optimization. ` +
    `A zero target indicates an unmapped region. The final region's length is not stored.</p><dl>`);
  out.push(renderDefinitionRow("Mapping direction", entry.type === IMAGE_DEBUG_TYPE_OMAP_TO_SRC
    ? "Optimized image to original source layout" : "Original source layout to optimized image"));
  out.push(renderDefinitionRow("Mapping records", String(records.length)));
  out.push(renderDefinitionRow("Unmapped regions", String(records.length - mapped.length)));
  out.push(renderDefinitionRow("Unchanged region starts",
    String(mapped.filter(record => record.rva === record.rvaTo).length)));
  out.push(renderDefinitionRow("Moved region starts",
    String(mapped.filter(record => record.rva !== record.rvaTo).length)));
  out.push(renderDefinitionRow("Input ordering", ordered ? "Strictly increasing" : "Ambiguous; not strictly increasing"));
  out.push(renderDefinitionRow("Mapped input bytes with known end", ordered ? humanSize(spanBytes) : "Unavailable",
    "Excludes the last record; this is not total code size."));
  out.push(`</dl>`);
  if (!records.length) out.push(`<p class="smallNote">No complete OMAP records.</p>`);
};