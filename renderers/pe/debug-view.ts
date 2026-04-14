"use strict";

import { humanSize, hex } from "../../binary-utils.js";
import { dd, safe } from "../../html-utils.js";
import type {
  PeDebugSection,
  PeWindowsParseResult
} from "../../analyzers/pe/index.js";
import type { PeDebugDirectoryEntry } from "../../analyzers/pe/debug/directory.js";
import { getDebugTypeInfo } from "./debug-type-info.js";
import { renderPeSectionEnd, renderPeSectionStart } from "./collapsible-section.js";

type DebugStorageInfo = { label: string; description: string };
type FileRange = { start: number; end: number };

const getDebugRawRange = (
  pe: PeWindowsParseResult,
  entry: PeDebugDirectoryEntry
): FileRange | null => {
  if ((entry.sizeOfData >>> 0) === 0) return null;
  const rawStart = entry.pointerToRawData || (
    entry.addressOfRawData ? pe.rvaToOff(entry.addressOfRawData) : null
  );
  return rawStart == null || rawStart < 0
    ? null
    : { start: rawStart, end: rawStart + (entry.sizeOfData >>> 0) };
};

const isRangeCoveredBySection = (
  pe: PeWindowsParseResult,
  range: FileRange
): boolean => pe.sections.some(section => {
  const start = section.pointerToRawData >>> 0;
  const end = start + (section.sizeOfRawData >>> 0);
  return range.start >= start && range.end <= end;
});

const getDebugStorageInfo = (
  pe: PeWindowsParseResult,
  entry: PeDebugDirectoryEntry
): DebugStorageInfo => {
  const rawRange = getDebugRawRange(pe, entry);
  if (!rawRange) {
    return {
      label: "UNRESOLVED",
      description: "Payload size is zero or the raw data location does not resolve to a file range."
    };
  }
  const hasRva = (entry.addressOfRawData >>> 0) !== 0;
  const coveredBySection = isRangeCoveredBySection(pe, rawRange);
  if (hasRva && coveredBySection) {
    return {
      label: "MAPPED",
      description: "Payload is section-backed and has a non-zero RVA, so it is mapped into the image."
    };
  }
  if (!hasRva && !coveredBySection) {
    return {
      label: "UNMAPPED",
      description: "Payload is addressed only by file pointer and is not covered by a section header."
    };
  }
  return {
    label: "INCONSISTENT",
    description: "RVA presence and section coverage disagree, so the payload is not cleanly mapped/unmapped."
  };
};

const hasDecodedPayload = (entry: PeDebugDirectoryEntry): boolean =>
  !!(entry.codeView || entry.vcFeature || entry.pogo);

const formatEntryType = (entry: PeDebugDirectoryEntry): string => {
  const typeInfo = getDebugTypeInfo(entry.type >>> 0);
  return `${safe(typeInfo.label)}<div class="valueHint">${hex(entry.type, 8)}</div>`;
};

const formatEntryStorage = (
  pe: PeWindowsParseResult,
  entry: PeDebugDirectoryEntry
): string => safe(getDebugStorageInfo(pe, entry).label);

const formatPogoRecordCount = (count: number): string =>
  `${count} record${count === 1 ? "" : "s"}`;

const getEntrySummary = (entry: PeDebugDirectoryEntry): string => {
  if (entry.codeView) return "CodeView RSDS record with PDB identity and path.";
  if (entry.vcFeature) return "MSVC toolchain counters such as /GS, /sdl, and guardN.";
  if (entry.pogo) {
    return `${entry.pogo.signatureName} profile-guided optimization map with ` +
      `${formatPogoRecordCount(entry.pogo.entries.length)}.`;
  }
  return getDebugTypeInfo(entry.type >>> 0).description;
};

const renderEntryCommonFields = (
  pe: PeWindowsParseResult,
  entry: PeDebugDirectoryEntry,
  out: string[]
): void => {
  const typeInfo = getDebugTypeInfo(entry.type >>> 0);
  const storageInfo = getDebugStorageInfo(pe, entry);
  out.push(`<dl>`);
  out.push(dd("Type", `${safe(typeInfo.label)} (${hex(entry.type, 8)})`, typeInfo.description));
  out.push(dd("Storage", safe(storageInfo.label), storageInfo.description));
  out.push(dd("Payload size", safe(humanSize(entry.sizeOfData))));
  out.push(dd("Raw RVA", safe(hex(entry.addressOfRawData, 8))));
  out.push(dd("Raw file ptr", safe(hex(entry.pointerToRawData, 8))));
  out.push(dd("What it contains", safe(getEntrySummary(entry))));
  out.push(`</dl>`);
};

const renderCodeViewFields = (entry: PeDebugDirectoryEntry, out: string[]): void => {
  if (!entry.codeView) return;
  out.push(
    `<div class="smallNote">CodeView RSDS records identify the PDB that matches this build. ` +
      `The debugger uses the GUID and Age to verify it loaded the right symbol file.</div>`
  );
  out.push(`<dl>`);
  out.push(dd("Signature", "RSDS", "Modern CodeView/PDB record format used by Microsoft tools."));
  out.push(
    dd(
      "GUID",
      safe((entry.codeView.guid || "").toUpperCase()),
      "PDB identity GUID used to match the correct PDB file."
    )
  );
  out.push(
    dd(
      "Age",
      safe(String(entry.codeView.age)),
      "PDB age; increments when the PDB is updated without a full rewrite."
    )
  );
  out.push(
    dd(
      "Path",
      safe(entry.codeView.path || "(no path)"),
      "Path recorded by the linker. It can be absolute and build-machine specific."
    )
  );
  out.push(`</dl>`);
};

const renderVcFeatureFields = (entry: PeDebugDirectoryEntry, out: string[]): void => {
  if (!entry.vcFeature) return;
  out.push(
    `<div class="smallNote">VC_FEATURE is MSVC toolchain metadata. Microsoft does not fully ` +
      `document these counters in the PE spec, so treat them as build telemetry rather than strict semantic flags.</div>`
  );
  out.push(
    `<table class="table" style="margin-top:.35rem"><thead><tr><th>Counter</th><th>Value</th><th>Meaning</th></tr></thead><tbody>`
  );
  out.push(
    `<tr><td>Pre-VC++ 11.00</td><td>${entry.vcFeature.preVc11}</td><td>Objects produced by older pre-VC++ 11 toolchains.</td></tr>`
  );
  out.push(
    `<tr><td>C/C++</td><td>${entry.vcFeature.cAndCpp}</td><td>Objects built from C or C++ compilation units.</td></tr>`
  );
  out.push(
    `<tr><td>/GS</td><td>${entry.vcFeature.gs}</td><td>Objects that use MSVC stack-cookie protection.</td></tr>`
  );
  out.push(
    `<tr><td>/sdl</td><td>${entry.vcFeature.sdl}</td><td>Objects built with additional Security Development Lifecycle checks.</td></tr>`
  );
  out.push(
    `<tr><td>guardN</td><td>${entry.vcFeature.guardN}</td><td>Toolchain-defined guard counter emitted by MSVC.</td></tr>`
  );
  out.push(`</tbody></table>`);
};

const renderPogoFields = (entry: PeDebugDirectoryEntry, out: string[]): void => {
  if (!entry.pogo) return;
  out.push(
    `<div class="smallNote">POGO records describe linker chunks used by profile-guided optimization ` +
      `or link-time code generation. The Name column usually contains linker section-group labels, not source-level function names.</div>`
  );
  out.push(`<dl>`);
  out.push(
    dd(
      "Signature",
      `${safe(entry.pogo.signatureName)} (${hex(entry.pogo.signature, 8)})`,
      "POGO payload flavor emitted by the linker."
    )
  );
  out.push(
    dd(
      "Entry count",
      safe(String(entry.pogo.entries.length)),
      "Number of chunk records stored in this POGO payload."
    )
  );
  out.push(`</dl>`);
  if (!entry.pogo.entries.length) return;
  out.push(
    `<table class="table" style="margin-top:.35rem"><thead><tr><th>#</th><th>Start RVA</th><th>Size</th><th>Name</th></tr></thead><tbody>`
  );
  entry.pogo.entries.forEach((pogoEntry, index) => {
    out.push(
      `<tr><td>${index + 1}</td><td>${hex(pogoEntry.startRva, 8)}</td><td>${humanSize(pogoEntry.size)}</td><td>${safe(pogoEntry.name || "(empty)")}</td></tr>`
    );
  });
  out.push(`</tbody></table>`);
};

const renderDecodedEntryDetails = (
  pe: PeWindowsParseResult,
  debug: PeDebugSection,
  out: string[]
): void => {
  const decodedEntries = debug.entries?.filter(hasDecodedPayload) ?? [];
  if (!decodedEntries.length) return;
  out.push(
    `<div class="smallNote" style="margin-top:.5rem">Decoded entry details explain the fields for ` +
      `recognized payload formats. The table above stays as a compact index; the sections below explain each decoded payload in full.</div>`
  );
  decodedEntries.forEach(entry => {
    const entryIndex = debug.entries?.indexOf(entry) ?? -1;
    const typeInfo = getDebugTypeInfo(entry.type >>> 0);
    const storageInfo = getDebugStorageInfo(pe, entry);
    out.push(
      `<details style="margin-top:.5rem"><summary style="cursor:pointer;padding:.25rem .5rem;border:1px solid var(--border2);border-radius:6px;background:var(--chip-bg)">Entry #${entryIndex + 1}: ${safe(typeInfo.label)} (${safe(storageInfo.label)})</summary>`
    );
    renderEntryCommonFields(pe, entry, out);
    renderCodeViewFields(entry, out);
    renderVcFeatureFields(entry, out);
    renderPogoFields(entry, out);
    out.push(`</details>`);
  });
};

const renderEntryTable = (
  pe: PeWindowsParseResult,
  debug: PeDebugSection,
  out: string[]
): void => {
  if (!debug.entries?.length) return;
  out.push(
    `<table class="table" style="margin-top:.35rem"><thead><tr><th>#</th><th>Type</th><th>Storage</th><th>Payload</th><th>Raw RVA</th><th>Raw file ptr</th><th>What it contains</th></tr></thead><tbody>`
  );
  debug.entries.forEach((entry, index) => {
    out.push(
      `<tr><td>${index + 1}</td><td>${formatEntryType(entry)}</td><td title="${safe(getDebugStorageInfo(pe, entry).description)}">${formatEntryStorage(pe, entry)}</td><td>${humanSize(entry.sizeOfData)}</td><td>${hex(entry.addressOfRawData, 8)}</td><td>${hex(entry.pointerToRawData, 8)}</td><td>${safe(getEntrySummary(entry))}</td></tr>`
    );
  });
  out.push(`</tbody></table>`);
};

const renderDebugIntro = (out: string[]): void => {
  out.push(
    `<div class="smallNote">IMAGE_DEBUG_DIRECTORY is an index of debug payloads. Each entry says ` +
      `what format is present, how large it is, and where the payload lives in the file. ` +
      `Storage tells you whether the payload is mapped through a section or only exists in raw file layout.</div>`
  );
};

export function renderDebug(pe: PeWindowsParseResult, out: string[]): void {
  if (!pe.debug) return;
  out.push(
    renderPeSectionStart(
      "Debug directory",
      `${pe.debug.entries?.length ?? 0} entr${(pe.debug.entries?.length ?? 0) === 1 ? "y" : "ies"}`
    )
  );
  renderDebugIntro(out);
  renderEntryTable(pe, pe.debug, out);
  renderDecodedEntryDetails(pe, pe.debug, out);
  if (pe.debug.warning) out.push(`<div class="smallNote">${safe(pe.debug.warning)}</div>`);
  out.push(renderPeSectionEnd());
}
