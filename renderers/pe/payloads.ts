"use strict";

import { hex, humanSize } from "../../binary-utils.js";
import type {
  PeExtractedPayload,
  PePayloadAnalysis,
  PePayloadFormat
} from "../../analyzers/pe/payloads.js";
import { renderDownloadButton } from "../download-button.js";
import { renderPeSectionEnd, renderPeSectionStart } from "./collapsible-section.js";

const PAYLOAD_FORMAT_LABELS: Readonly<Record<PePayloadFormat, string>> = {
  pe: "PE executable",
  rar: "RAR archive",
  sevenzip: "7z archive"
};

const renderPayloadDownloadButton = (payload: PeExtractedPayload): string =>
  renderDownloadButton(`Download ${PAYLOAD_FORMAT_LABELS[payload.format]}`, [
    ["data-pe-payload-download"],
    ["data-payload-start", payload.start],
    ["data-payload-end", payload.end],
    ["data-payload-format", payload.format]
  ]);

const renderPayloadEntry = (payload: PeExtractedPayload, label: string): string =>
  `<div class="pePayloadEntry"><div><b>${label}</b> - ` +
  `${PAYLOAD_FORMAT_LABELS[payload.format]}` +
  `<div class="smallNote">File range ${hex(payload.start, 8)}-${hex(payload.end, 8)}; ` +
  `${humanSize(payload.end - payload.start)}</div></div>` +
  `${renderPayloadDownloadButton(payload)}</div>`;

export const renderPePayloadEntries = (
  payloads: readonly PeExtractedPayload[],
  label = "Validated payload"
): string => payloads.map(payload => renderPayloadEntry(payload, label)).join("");

export const getStandalonePePayloads = (
  analysis: PePayloadAnalysis | null | undefined
): PeExtractedPayload[] => analysis?.entries.filter(payload => payload.source !== "nsis") ?? [];

export const getPePayloadSectionDescriptor = (
  analysis: PePayloadAnalysis | null | undefined
) => {
  const count = getStandalonePePayloads(analysis).length;
  return count ? {
    key: "payloads" as const,
    summary: `${count} validated payload(s)`,
    title: "Embedded payloads"
  } : null;
};

export const renderPePayloads = (
  analysis: PePayloadAnalysis | null | undefined,
  out: string[]
): void => {
  const payloads = getStandalonePePayloads(analysis);
  if (!payloads.length) return;
  out.push(renderPeSectionStart(
    "Embedded payloads",
    `${payloads.length} validated ${payloads.length === 1 ? "payload" : "payloads"}`
  ));
  out.push(renderPePayloadEntries(payloads));
  out.push(renderPeSectionEnd());
};
