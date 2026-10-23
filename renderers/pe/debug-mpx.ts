import type { PeDebugDirectoryEntry } from "../../analyzers/pe/debug/directory.js";
import { renderDefinitionRow, renderFlagChips } from "../../html-utils.js";

// Flag meanings from the public PE Bliss 2 JRBP layout:
// https://github.com/dragon-dreamer/pe_bliss2/blob/e4d56862f2ccd9ed33fa5d4f6c51dfc4d075996f/pe_bliss2/include/pe_bliss2/detail/debug/image_debug_directory.h#L297
export const renderMpxDebug = (entry: PeDebugDirectoryEntry, out: string[]): void => {
  if (!entry.mpx) return;
  const mpx = entry.mpx;
  out.push(`<dl>${renderDefinitionRow("MPX configuration", renderFlagChips(mpx.flags, [
    [1, "MPX enabled", "Enable Intel Memory Protection Extensions for this application."],
    [2, "Driver runtime", "Use driver runtime support; when clear, use a runtime DLL."],
    [4, "Fail fast", "Terminate on a bounds violation; when clear, pass it to the application exception handler."]
  ]))}`);
  out.push(renderDefinitionRow("Uninterpreted data",
    `3 unnamed fields; ${[mpx.unknown1, mpx.unknown2, mpx.unknown3].filter(value => value !== 0).length} nonzero.`,
    "The public JRBP layout does not establish the meaning of these fields. Their values are retained in the analysis."));
  out.push(`</dl>`);
};
