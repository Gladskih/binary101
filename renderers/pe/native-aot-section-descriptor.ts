"use strict";

import type { PeNativeAotAnalysis } from "../../analyzers/pe/native-aot.js";

export const getNativeAotSectionDescriptor = (
  analysis: PeNativeAotAnalysis | null | undefined
): { key: "native-aot"; summary: string; title: string } => ({
  key: "native-aot",
  summary: analysis?.status === "confirmed"
    ? `${analysis.sections.length} ${analysis.sections.length === 1 ? "section" : "sections"}`
    : "conservative evidence",
  title: analysis?.status === "confirmed" ? "NativeAOT metadata" : "Native AOT candidate"
});
