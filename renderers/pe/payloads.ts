"use strict";

import { hex, humanSize } from "../../binary-utils.js";
import { escapeHtml } from "../../html-utils.js";
import type {
  PeExtractedPayload,
  PePayloadAnalysis,
  PePayloadFormat,
  PePayloadProvenance
} from "../../analyzers/pe/payloads.js";
import { knownResourceType } from "../../analyzers/pe/resources/type-names.js";
import { renderDownloadButton } from "../download-button.js";
import { renderPeSectionEnd, renderPeSectionStart } from "./collapsible-section.js";

type PePayloadSection = "appended" | "resource";

const PAYLOAD_FORMAT_LABELS: Readonly<Record<PePayloadFormat, string>> = {
  pe: "PE-signature resource object",
  rar: "RAR archive",
  sevenzip: "7z archive"
};

const resourcePathNode = (node: { id: number | null; name: string | null }, index: number): string => {
  if (node.name != null) return node.name;
  if (node.id == null) return "(unnamed)";
  return index === 0 ? knownResourceType(node.id) ?? `TYPE_${node.id}` : `#${node.id}`;
};

const resourcePath = (provenance: Extract<PePayloadProvenance, { location: "resource" }>): string =>
  provenance.resourcePath.map(resourcePathNode).join(" / ");

const payloadLocation = (payload: PeExtractedPayload): string =>
  payload.provenance.location === "overlay"
    ? "True PE overlay"
    : `PE resource leaf: ${resourcePath(payload.provenance)}`;

const payloadDiscovery = (payload: PeExtractedPayload): string =>
  payload.provenance.discovery === "archive-scan"
    ? "Bounded scan found an archive signature and its validated end boundary."
    : "The PE resource directory names this data leaf.";

const payloadAssociation = (payload: PeExtractedPayload): string =>
  payload.provenance.location === "overlay" &&
  payload.provenance.association === "nsis-installer-data"
    ? "The complete range lies inside the validated NSIS installer-data boundary."
    : payload.provenance.location === "overlay"
      ? "No recognized installer or packer owns this range."
      : "This object is the exact byte range of the named resource leaf.";

const payloadValidation = (payload: PeExtractedPayload): string =>
  payload.provenance.validation === "rar-end-archive"
    ? "RAR structure and the end-of-archive header establish the exact range."
    : payload.provenance.validation === "sevenzip-next-header"
      ? "7z SignatureHeader and NextHeader bounds and checksums establish the exact range."
      : "MZ, bounded e_lfanew, and PE signature only; this is not a recursive PE parse.";

const renderPayloadDownloadButton = (payload: PeExtractedPayload): string =>
  renderDownloadButton(`Download ${PAYLOAD_FORMAT_LABELS[payload.format]}`, [
    ["data-pe-payload-download"],
    ["data-payload-start", payload.start],
    ["data-payload-end", payload.end],
    ["data-payload-format", payload.format]
  ]);

const renderPayloadRow = (payload: PeExtractedPayload): string =>
  `<tr><td><b>${PAYLOAD_FORMAT_LABELS[payload.format]}</b><br><span class="smallNote">` +
  `${hex(payload.start, 8)}-${hex(payload.end, 8)}; ${humanSize(payload.end - payload.start)}` +
  `</span></td><td>${escapeHtml(payloadLocation(payload))}</td>` +
  `<td class="smallNote">${escapeHtml(payloadDiscovery(payload))}</td>` +
  `<td class="smallNote">${escapeHtml(payloadAssociation(payload))}</td>` +
  `<td class="smallNote">${escapeHtml(payloadValidation(payload))}</td>` +
  `<td>${renderPayloadDownloadButton(payload)}</td></tr>`;

export const renderPePayloadEntries = (
  payloads: readonly PeExtractedPayload[],
  label = "Detected payloads"
): string => !payloads.length ? "" :
  `<div class="tableWrap"><table class="table pePayloadTable"><caption>${escapeHtml(label)}</caption>` +
  `<thead><tr><th>Object</th><th>Location</th><th>Found by</th><th>Relationship</th>` +
  `<th>Validation</th><th>Action</th></tr></thead><tbody>` +
  payloads.map(renderPayloadRow).join("") + `</tbody></table></div>`;

const isNsisPayload = (payload: PeExtractedPayload): boolean =>
  payload.provenance.location === "overlay" &&
  payload.provenance.association === "nsis-installer-data";

export const getStandalonePePayloads = (
  analysis: PePayloadAnalysis | null | undefined
): PeExtractedPayload[] => analysis?.entries.filter(payload =>
  payload.provenance.location === "overlay" && !isNsisPayload(payload)
) ?? [];

export const getResourcePePayloads = (
  analysis: PePayloadAnalysis | null | undefined
): PeExtractedPayload[] => analysis?.entries.filter(payload => payload.provenance.location === "resource") ?? [];

export const getPePayloadSectionDescriptor = (
  analysis: PePayloadAnalysis | null | undefined
) => {
  const count = getStandalonePePayloads(analysis).length;
  return count ? {
    summary: `${count} ${count === 1 ? "archive" : "archives"}`,
    title: count === 1 ? "Appended archive" : "Appended archives"
  } : null;
};

export const getResourcePayloadSectionDescriptor = (
  analysis: PePayloadAnalysis | null | undefined
) => {
  const count = getResourcePePayloads(analysis).length;
  return count ? {
    summary: `${count} PE-signature ${count === 1 ? "object" : "objects"}`,
    title: "PE-signature resource objects"
  } : null;
};

const payloadsForSection = (
  analysis: PePayloadAnalysis | null | undefined,
  section: PePayloadSection
): PeExtractedPayload[] => section === "appended"
  ? getStandalonePePayloads(analysis)
  : getResourcePePayloads(analysis);

const payloadSectionTitle = (section: PePayloadSection): string => section === "appended"
  ? "Appended archive"
  : "PE-signature resource objects";

export const renderPePayloads = (
  analysis: PePayloadAnalysis | null | undefined,
  section: PePayloadSection,
  out: string[]
): void => {
  const payloads = payloadsForSection(analysis, section);
  if (!payloads.length) return;
  out.push(renderPeSectionStart(payloadSectionTitle(section), `${payloads.length} detected`));
  out.push(renderPePayloadEntries(payloads));
  out.push(renderPeSectionEnd());
};
