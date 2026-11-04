import type { PdfParseResult } from "../../../pdf/types.js";
import type { ZipParseResult } from "../../../zip/types.js";
import type { AviParseResult } from "../../../avi/types.js";
import type { ResourcePreviewResult } from "./types.js";

export type ResourceEmbeddedDocument = { format: "PDF"; analysis?: PdfParseResult }
  | { format: "ZIP"; analysis?: ZipParseResult } | { format: "AVI"; analysis?: AviParseResult };

const inspectAvi = async (file: File): Promise<ResourcePreviewResult> => {
  const format = "AVI";
  const analysis = await (await import("../../../avi/index.js")).parseAvi(file);
  return { preview: { previewKind: "nested", embeddedDocument: { format, ...(analysis ? { analysis } : {}) } },
    issues: analysis?.issues ?? ["Embedded AVI could not be analyzed."] };
};

export const inspectEmbeddedDocument = async (
  data: Uint8Array, format: ResourceEmbeddedDocument["format"]
): Promise<ResourcePreviewResult> => {
  const file = new File([data as Uint8Array<ArrayBuffer>], `resource.${format.toLowerCase()}`);
  // Load the existing local analyzers only after an explicit inspection request.
  if (format === "PDF") {
    const analysis = await (await import("../../../pdf/index.js")).parsePdf(file);
    return { preview: { previewKind: "nested", embeddedDocument: { format, ...(analysis ? { analysis } : {}) } },
      issues: analysis?.issues ?? ["Embedded PDF could not be analyzed."] };
  }
  if (format === "ZIP") {
    const analysis = await (await import("../../../zip/index.js")).parseZip(file);
    return { preview: { previewKind: "nested", embeddedDocument: { format, ...(analysis ? { analysis } : {}) } },
      issues: analysis?.issues ?? ["Embedded ZIP could not be analyzed."] };
  }
  return inspectAvi(file);
};
