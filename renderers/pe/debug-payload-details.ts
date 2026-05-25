"use strict";

import { humanSize, hex } from "../../binary-utils.js";
import { renderDefinitionRow, renderFlagChips, escapeHtml } from "../../html-utils.js";
import type { PeDebugSection, PeWindowsParseResult } from "../../analyzers/pe/index.js";
import type { PeDebugDirectoryEntry } from "../../analyzers/pe/debug/directory.js";
import { EX_DLL_CHARACTERISTICS_FLAGS } from "../../analyzers/pe/constants.js";
import { getDebugTypeInfo } from "./debug-type-info.js";
import { getDebugStorageInfo, getEntrySummary } from "./debug-entry-summary.js";

const hasDecodedPayload = (entry: PeDebugDirectoryEntry): boolean =>
  !!(
    entry.codeView ||
    entry.fpo ||
    entry.misc ||
    entry.vcFeature ||
    entry.pogo ||
    entry.repro ||
    entry.embeddedPortablePdb ||
    entry.pdbChecksum ||
    entry.exDllCharacteristics ||
    entry.r2rPerfMap ||
    entry.rawPayload
  );

const formatByteHex = (value: number): string => value.toString(16).padStart(2, "0");
const formatBytes = (bytes: number[]): string => bytes.map(formatByteHex).join(" ");
const formatByteString = (bytes: number[]): string => bytes.map(formatByteHex).join("");

const renderEntryCommonFields = (
  pe: PeWindowsParseResult,
  entry: PeDebugDirectoryEntry,
  out: string[]
): void => {
  const typeInfo = getDebugTypeInfo(entry.type >>> 0);
  const storageInfo = getDebugStorageInfo(pe, entry);
  out.push(`<dl>`);
  out.push(renderDefinitionRow("Type", `${escapeHtml(typeInfo.label)} (${hex(entry.type, 8)})`, typeInfo.description));
  out.push(renderDefinitionRow("Storage", escapeHtml(storageInfo.label), storageInfo.description));
  out.push(renderDefinitionRow("Payload size", escapeHtml(humanSize(entry.sizeOfData))));
  out.push(renderDefinitionRow("Raw RVA", escapeHtml(hex(entry.addressOfRawData, 8))));
  out.push(renderDefinitionRow("Raw file ptr", escapeHtml(hex(entry.pointerToRawData, 8))));
  out.push(renderDefinitionRow("What it contains", escapeHtml(getEntrySummary(entry))));
  out.push(`</dl>`);
};

const renderCodeViewFields = (entry: PeDebugDirectoryEntry, out: string[]): void => {
  if (!entry.codeView) return;
  out.push(`<dl>`);
  if (entry.codeView.signature === "NB10") {
    out.push(renderDefinitionRow("Signature", "NB10", "Legacy CodeView/PDB record format."));
    out.push(renderDefinitionRow("Offset", escapeHtml(hex(entry.codeView.offset ?? 0, 8))));
    out.push(renderDefinitionRow("Timestamp", escapeHtml(hex(entry.codeView.timestamp ?? 0, 8))));
  } else {
    out.push(renderDefinitionRow(
      "Signature",
      "RSDS",
      "Modern CodeView/PDB record format used by Microsoft tools."
    ));
    out.push(renderDefinitionRow(
      "GUID",
      escapeHtml(entry.codeView.guid.toUpperCase()),
      "PDB identity GUID used to match the correct PDB file."
    ));
  }
  out.push(renderDefinitionRow("Age", escapeHtml(String(entry.codeView.age))));
  out.push(renderDefinitionRow("Path", escapeHtml(entry.codeView.path || "(no path)")));
  out.push(`</dl>`);
};

const renderFpoFields = (entry: PeDebugDirectoryEntry, out: string[]): void => {
  if (!entry.fpo) return;
  out.push(`<dl>${renderDefinitionRow("Record count", escapeHtml(String(entry.fpo.records.length)))}</dl>`);
  out.push(
    `<table class="table" style="margin-top:.35rem"><thead><tr><th>#</th>` +
      `<th>Start</th><th>Size</th><th>Locals</th><th>Params</th>` +
      `<th>Prolog</th><th>Regs</th><th>Frame</th></tr></thead><tbody>`
  );
  entry.fpo.records.slice(0, 25).forEach((record, index) => {
    out.push(
      `<tr><td>${index + 1}</td><td>${hex(record.startOffset, 8)}</td>` +
        `<td>${humanSize(record.procedureSize)}</td><td>${record.localDwordCount}</td>` +
        `<td>${record.parameterDwordCount}</td><td>${record.prologByteCount}</td>` +
        `<td>${record.savedRegisterCount}</td><td>${record.frameType}</td></tr>`
    );
  });
  out.push(`</tbody></table>`);
};

const renderMiscFields = (entry: PeDebugDirectoryEntry, out: string[]): void => {
  if (!entry.misc) return;
  out.push(`<dl>`);
  out.push(renderDefinitionRow("Data type", escapeHtml(hex(entry.misc.dataType, 8))));
  out.push(renderDefinitionRow("Length", escapeHtml(humanSize(entry.misc.length))));
  out.push(renderDefinitionRow("Encoding", entry.misc.unicode ? "UTF-16LE" : "ANSI"));
  out.push(renderDefinitionRow("Text", escapeHtml(entry.misc.text || "(empty)")));
  out.push(`</dl>`);
};

const renderVcFeatureFields = (entry: PeDebugDirectoryEntry, out: string[]): void => {
  if (!entry.vcFeature) return;
  out.push(
    `<table class="table" style="margin-top:.35rem"><thead><tr>` +
      `<th>Counter</th><th>Value</th><th>Meaning</th></tr></thead><tbody>`
  );
  out.push(
    `<tr><td>Pre-VC++ 11.00</td><td>${entry.vcFeature.preVc11}</td>` +
      `<td>Objects produced by older pre-VC++ 11 toolchains.</td></tr>`
  );
  out.push(
    `<tr><td>C/C++</td><td>${entry.vcFeature.cAndCpp}</td>` +
      `<td>Objects built from C or C++ compilation units.</td></tr>`
  );
  out.push(
    `<tr><td>/GS</td><td>${entry.vcFeature.gs}</td>` +
      `<td>Objects that use MSVC stack-cookie protection.</td></tr>`
  );
  out.push(
    `<tr><td>/sdl</td><td>${entry.vcFeature.sdl}</td>` +
      `<td>Objects built with additional Security Development Lifecycle checks.</td></tr>`
  );
  out.push(
    `<tr><td>guardN</td><td>${entry.vcFeature.guardN ?? "-"}</td>` +
      `<td>Toolchain-defined guard counter emitted by MSVC.</td></tr>`
  );
  out.push(`</tbody></table>`);
};

const renderPogoFields = (entry: PeDebugDirectoryEntry, out: string[]): void => {
  if (!entry.pogo) return;
  out.push(
    `<div class="smallNote">POGO records describe linker chunks used by profile-guided optimization ` +
      `or link-time code generation.</div>`
  );
  out.push(`<dl>`);
  out.push(renderDefinitionRow(
    "Signature",
    `${escapeHtml(entry.pogo.signatureName)} (${hex(entry.pogo.signature, 8)})`
  ));
  out.push(renderDefinitionRow("Entry count", escapeHtml(String(entry.pogo.entries.length))));
  out.push(`</dl>`);
  if (!entry.pogo.entries.length) return;
  out.push(
    `<table class="table" style="margin-top:.35rem"><thead><tr><th>#</th>` +
      `<th>Start RVA</th><th>Size</th><th>Name</th></tr></thead><tbody>`
  );
  entry.pogo.entries.forEach((pogoEntry, index) => {
    out.push(
      `<tr><td>${index + 1}</td><td>${hex(pogoEntry.startRva, 8)}</td>` +
        `<td>${humanSize(pogoEntry.size)}</td>` +
        `<td>${escapeHtml(pogoEntry.name || "(empty)")}</td></tr>`
    );
  });
  out.push(`</tbody></table>`);
};

const renderReproFields = (entry: PeDebugDirectoryEntry, out: string[]): void => {
  if (entry.repro) {
    out.push(`<dl>`);
    out.push(renderDefinitionRow(
      "Hash length",
      entry.repro.hashLength == null ? "none" : String(entry.repro.hashLength)
    ));
    out.push(`</dl>`);
  }
};

const renderEmbeddedPortablePdbFields = (entry: PeDebugDirectoryEntry, out: string[]): void => {
  if (entry.embeddedPortablePdb) {
    out.push(`<dl>${renderDefinitionRow("Signature", escapeHtml(entry.embeddedPortablePdb.signature))}`);
    out.push(renderDefinitionRow(
      "Compressed size",
      escapeHtml(humanSize(entry.embeddedPortablePdb.compressedSize))
    ));
    out.push(renderDefinitionRow(
      "Uncompressed size",
      escapeHtml(humanSize(entry.embeddedPortablePdb.uncompressedSize))
    ));
    out.push(`</dl>`);
  }
};

const renderPdbChecksumFields = (entry: PeDebugDirectoryEntry, out: string[]): void => {
  if (entry.pdbChecksum) {
    out.push(`<dl>${renderDefinitionRow("Algorithm", escapeHtml(entry.pdbChecksum.algorithmName || "(empty)"))}`);
    out.push(renderDefinitionRow(
      "Checksum",
      `<span class="mono">${formatByteString(entry.pdbChecksum.checksumBytes)}</span>`
    ));
    out.push(`</dl>`);
  }
};

const renderExDllCharacteristicsFields = (entry: PeDebugDirectoryEntry, out: string[]): void => {
  if (entry.exDllCharacteristics) {
    out.push(`<dl>${renderDefinitionRow(
      "Bits",
      `<div class="mono">${escapeHtml(hex(entry.exDllCharacteristics.value >>> 0, 8))}</div>` +
        renderFlagChips(entry.exDllCharacteristics.value, EX_DLL_CHARACTERISTICS_FLAGS)
    )}</dl>`);
  }
};

const renderR2rPerfMapFields = (entry: PeDebugDirectoryEntry, out: string[]): void => {
  if (!entry.r2rPerfMap) return;
  out.push(`<dl>`);
  out.push(renderDefinitionRow("Magic", escapeHtml(entry.r2rPerfMap.magic)));
  out.push(renderDefinitionRow("Version", escapeHtml(String(entry.r2rPerfMap.version))));
  out.push(renderDefinitionRow(
    "Signature",
    `<span class="mono">${formatByteString(entry.r2rPerfMap.signatureBytes)}</span>`
  ));
  out.push(renderDefinitionRow("Path", escapeHtml(entry.r2rPerfMap.path || "(no path)")));
  out.push(`</dl>`);
};

const renderRawPayloadFields = (entry: PeDebugDirectoryEntry, out: string[]): void => {
  if (entry.rawPayload) {
    out.push(`<dl>`);
    out.push(renderDefinitionRow(
      "Preview",
      `<span class="mono">${formatBytes(entry.rawPayload.previewBytes)}</span>`
    ));
    out.push(`</dl>`);
  }
};

export const renderDecodedEntryDetails = (
  pe: PeWindowsParseResult,
  debug: PeDebugSection,
  out: string[]
): void => {
  const decodedEntries = debug.entries?.filter(hasDecodedPayload) ?? [];
  if (!decodedEntries.length) return;
  out.push(
    `<div class="smallNote" style="margin-top:.5rem">Decoded entry details explain the fields ` +
      `for recognized payload formats. The table above stays as a compact index; the sections ` +
      `below explain each decoded payload in full.</div>`
  );
  decodedEntries.forEach(entry => {
    const typeInfo = getDebugTypeInfo(entry.type >>> 0);
    const storageInfo = getDebugStorageInfo(pe, entry);
    out.push(
      `<details style="margin-top:.5rem"><summary style="cursor:pointer;padding:.25rem .5rem;` +
        `border:1px solid var(--border2);border-radius:6px;background:var(--chip-bg)">` +
        `Entry #${(debug.entries?.indexOf(entry) ?? -1) + 1}: ${escapeHtml(typeInfo.label)} ` +
        `(${escapeHtml(storageInfo.label)})</summary>`
    );
    renderEntryCommonFields(pe, entry, out);
    renderCodeViewFields(entry, out);
    renderFpoFields(entry, out);
    renderMiscFields(entry, out);
    renderVcFeatureFields(entry, out);
    renderPogoFields(entry, out);
    renderReproFields(entry, out);
    renderEmbeddedPortablePdbFields(entry, out);
    renderPdbChecksumFields(entry, out);
    renderExDllCharacteristicsFields(entry, out);
    renderR2rPerfMapFields(entry, out);
    renderRawPayloadFields(entry, out);
    out.push(`</details>`);
  });
};
