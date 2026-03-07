"use strict";

import { dd, safe } from "../../html-utils.js";
import type { MachOCodeSignature } from "../../analyzers/macho/types.js";
import {
  codeDirectoryExecSegLabels,
  codeDirectoryFlagLabels,
  codeDirectoryHashLabel,
  codeSignatureBlobLabel,
  codeSignatureSlotLabelFor,
  pageSizeBytes
} from "./codesign-semantics.js";
import { formatByteSize, formatHex, formatList } from "./value-format.js";

const renderCodeSignature = (signature: MachOCodeSignature): string => {
  const details: string[] = [
    dd("Blob", safe(`${codeSignatureBlobLabel(signature.magic)} @ ${formatHex(signature.dataoff)}`)),
    dd("Size", safe(formatByteSize(signature.datasize)))
  ];
  if (signature.blobCount != null) details.push(dd("Indexed blobs", safe(String(signature.blobCount))));
  if (signature.codeDirectory) {
    const codeDirectory = signature.codeDirectory;
    details.push(dd("Identifier", `<span class="mono">${safe(codeDirectory.identifier || "-")}</span>`));
    if (codeDirectory.teamIdentifier) {
      details.push(dd("Team", `<span class="mono">${safe(codeDirectory.teamIdentifier)}</span>`));
    }
    details.push(
      dd(
        "CodeDirectory",
        safe(
          `v${formatHex(codeDirectory.version)}; ${codeDirectoryHashLabel(codeDirectory.hashType)}; ` +
            `${codeDirectory.nCodeSlots} code slots`
        )
      )
    );
    details.push(dd("Flags", formatList(codeDirectoryFlagLabels(codeDirectory.flags))));
    const execSegLabels = codeDirectoryExecSegLabels(codeDirectory.execSegFlags);
    if (execSegLabels.length) details.push(dd("Exec segment flags", formatList(execSegLabels)));
    const pageSize = pageSizeBytes(codeDirectory.pageSizeShift);
    if (pageSize != null) details.push(dd("Page size", safe(formatByteSize(pageSize))));
  }
  const slots = !signature.slots.length
    ? ""
    : `<div class="tableWrap"><table class="table"><thead><tr><th>Slot</th><th>Type</th><th>Magic</th><th>Length</th></tr></thead><tbody>` +
        signature.slots
          .map(
            slot =>
              `<tr><td><span class="mono">${safe(formatHex(slot.offset))}</span></td>` +
              `<td>${safe(codeSignatureSlotLabelFor(slot.type))}</td>` +
              `<td>${safe(slot.magic != null ? codeSignatureBlobLabel(slot.magic) : "-")}</td>` +
              `<td>${safe(slot.length != null ? String(slot.length) : "-")}</td></tr>`
          )
          .join("") +
        `</tbody></table></div>`;
  return `<section><h4 style="margin:0 0 .5rem 0;font-size:.9rem">Code signing</h4><dl>${details.join("")}</dl>${slots}</section>`;
};

export { renderCodeSignature };
