import type { PeDebugSection } from "../../analyzers/pe/core/parse-result.js";
import type { PeLazySectionDescriptor } from "./lazy-section-shells.js";

export const getPeDebugSectionDescriptor = (debug: PeDebugSection | null): PeLazySectionDescriptor => {
  const { entries = [], td32Sources = [] } = debug ?? {};
  return { key: "debug", title: td32Sources.length ? "Debug information" : "Debug directory",
    summary: `${entries.length} entr${entries.length === 1 ? "y" : "ies"}` +
      (td32Sources.length ? `; TD32 sources: ${td32Sources.length}` : "") };
};
