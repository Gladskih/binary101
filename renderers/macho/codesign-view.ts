"use strict";

import { renderDefinitionRow, escapeHtml } from "../../html-utils.js";
import type { MachOCodeSignature } from "../../analyzers/macho/types.js";
import {
  codeDirectoryExecSegLabels,
  codeDirectoryFlagLabels,
  codeDirectoryHashLabel,
  codeSignatureBlobLabel,
  codeSignatureSlotLabelFor,
  pageSizeLabel
} from "./codesign-semantics.js";
import { formatByteSize, formatFileOffset, formatHex, formatList } from "./value-format.js";

const renderCodeSignature = (signature: MachOCodeSignature, imageOffset = 0): string => {
  const details: string[] = [
    renderDefinitionRow(
      "Blob",
      escapeHtml(`${codeSignatureBlobLabel(signature.magic)} @ ${formatFileOffset(imageOffset, signature.dataoff)}`)
    ),
    renderDefinitionRow("Size", escapeHtml(formatByteSize(signature.datasize)))
  ];
  if (signature.blobCount != null) details.push(renderDefinitionRow("Indexed blobs", escapeHtml(String(signature.blobCount))));
  if (signature.codeDirectory) {
    const codeDirectory = signature.codeDirectory;
    details.push(renderDefinitionRow("Identifier", `<span class="mono">${escapeHtml(codeDirectory.identifier || "-")}</span>`));
    if (codeDirectory.teamIdentifier) {
      details.push(renderDefinitionRow("Team", `<span class="mono">${escapeHtml(codeDirectory.teamIdentifier)}</span>`));
    }
    details.push(
      renderDefinitionRow(
        "CodeDirectory",
        escapeHtml(
          `v${formatHex(codeDirectory.version)}; ${codeDirectoryHashLabel(codeDirectory.hashType)}; ` +
            `${codeDirectory.nCodeSlots} code slots`
        )
      )
    );
    details.push(renderDefinitionRow("Flags", formatList(codeDirectoryFlagLabels(codeDirectory.flags))));
    const execSegLabels = codeDirectoryExecSegLabels(codeDirectory.execSegFlags);
    if (execSegLabels.length) details.push(renderDefinitionRow("Exec segment flags", formatList(execSegLabels)));
    details.push(renderDefinitionRow("Page size", escapeHtml(pageSizeLabel(codeDirectory.pageSizeShift))));
  }
  const slots = !signature.slots.length
    ? ""
    : `<div class="tableWrap"><table class="table"><thead><tr><th>Slot</th><th>Type</th><th>Magic</th><th>Length</th></tr></thead><tbody>` +
        signature.slots
          .map(
            slot =>
              `<tr><td><span class="mono">${escapeHtml(formatHex(slot.offset))}</span></td>` +
              `<td>${escapeHtml(codeSignatureSlotLabelFor(slot.type))}</td>` +
              `<td>${escapeHtml(slot.magic != null ? codeSignatureBlobLabel(slot.magic) : "-")}</td>` +
              `<td>${escapeHtml(slot.length != null ? String(slot.length) : "-")}</td></tr>`
          )
          .join("") +
        `</tbody></table></div>`;
  return `<section><h4 style="margin:0 0 .5rem 0;font-size:.9rem">Code signing</h4><dl>${details.join("")}</dl>${slots}</section>`;
};

export { renderCodeSignature };
