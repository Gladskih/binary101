import type { MsvcRttiAnalysis } from "../../analyzers/pe/msvc-rtti/types.js";
import { getMsvcRttiSummaryCounts } from "./msvc-rtti.js";

export const getMsvcRttiSectionDescriptor = (analysis: MsvcRttiAnalysis) => {
  const counts = getMsvcRttiSummaryCounts(analysis);
  return {
    key: "msvc-rtti" as const,
    summary: `${counts.types} ${counts.types === 1 ? "type" : "types"} / ` +
      `${counts.completeObjectLocators} COL / ` +
      `${counts.vftables} ${counts.vftables === 1 ? "vftable" : "vftables"}`,
    title: "Microsoft C++ RTTI"
  };
};
