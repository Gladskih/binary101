import type { ResourceEmbeddedDocument } from "../../analyzers/pe/resources/preview/embedded-document.js";
import type { ResourcePreviewContext } from "./resource-preview-context.js";
import { escapeHtmlText } from "../../html-utils.js";

const renderPdf = (document: Extract<ResourceEmbeddedDocument, { format: "PDF" }>): string => {
    const pdf = document.analysis!;
    const fields = [["Version", pdf.header.version], ["Pages", pdf.pages?.count],
      ["Title", pdf.info?.title], ["Author", pdf.info?.author], ["Producer", pdf.info?.producer],
      ["Cross-reference", pdf.xref?.kind]];
    return `<table class="table"><tbody>${fields.map(([key, value]) => `<tr>` +
      `<th scope="row">${key}</th><td>${escapeHtmlText(value ?? "—")}</td></tr>`).join("")}` +
      `</tbody></table>`;
};

const renderZip = (document: Extract<ResourceEmbeddedDocument, { format: "ZIP" }>): string => {
    return `<p>ZIP: ${document.analysis!.eocd.totalEntries} declared entries</p>` +
      `<table class="table"><thead><tr><th>Name</th><th>Method</th><th>Compressed</th>` +
      `<th>Uncompressed</th><th>Encrypted</th></tr></thead><tbody>` +
      (document.analysis!.centralDirectory?.entries ?? []).map(entry => `<tr>` +
        `<td>${escapeHtmlText(entry.fileName)}</td><td>${escapeHtmlText(entry.compressionName)}</td>` +
        `<td>${entry.compressedSize}</td><td>${entry.uncompressedSize}</td>` +
        `<td>${entry.isEncrypted ? "Yes" : "No"}</td></tr>`).join("") + `</tbody></table>`;
};

const renderAvi = (document: Extract<ResourceEmbeddedDocument, { format: "AVI" }>): string => {
  const avi = document.analysis!;
  return `<p>AVI ${avi.mainHeader?.width ?? "?"}×${avi.mainHeader?.height ?? "?"}; ` +
    `${avi.mainHeader?.totalFrames ?? "?"} frames; ${avi.mainHeader?.frameRate ?? "?"} fps.</p>` +
    `<table class="table"><thead><tr><th>Stream</th><th>Type</th><th>Codec</th><th>Name</th>` +
    `</tr></thead><tbody>${avi.streams.map(stream => `<tr><td>${stream.index}</td>` +
      `<td>${escapeHtmlText(stream.header?.type ?? "—")}</td>` +
      `<td>${escapeHtmlText(stream.header?.handler ?? "—")}</td><td>${escapeHtmlText(stream.name ?? "—")}</td>` +
      `</tr>`).join("")}</tbody></table>`;
};

export const renderEmbeddedDocument = (
  document: ResourceEmbeddedDocument, context?: ResourcePreviewContext
): string => {
  if (!document.analysis) {
    const source = context?.source;
    return `<p>Embedded ${document.format}</p>` + (source ? `<button type="button" ` +
      `data-pe-resource-preview="${source.group}-${source.entry}-${source.language}">` +
      `Inspect ${document.format}</button>` : "");
  }
  if (document.format === "PDF") return renderPdf(document);
  if (document.format === "ZIP") return renderZip(document);
  return renderAvi(document);
};
