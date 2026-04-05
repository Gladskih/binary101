"use strict";

import { humanSize, hex } from "../../binary-utils.js";
import { dd, safe } from "../../html-utils.js";
import type {
  PeDebugSection,
  PeWindowsParseResult
} from "../../analyzers/pe/index.js";
import type { PeDebugDirectoryEntry } from "../../analyzers/pe/debug-directory.js";

type DebugTypeInfo = { label: string; description: string };
type DebugStorageInfo = { label: string; description: string };
type FileRange = { start: number; end: number };
type CountedChip = { count: number; label: string; description: string };

// Microsoft PE format, "Debug Type":
// https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#debug-directory-image-only
// LLVM COFF DebugType enum fills in additional toolchain-defined names such as
// VC_FEATURE / POGO / ILTCG / MPX:
// https://llvm.org/doxygen/namespacellvm_1_1COFF.html
const DEBUG_TYPE_INFOS: Record<number, DebugTypeInfo> = {
  0: { label: "UNKNOWN", description: "Unknown debug format ignored by tools." },
  1: {
    label: "COFF",
    description: "COFF line numbers, symbol table, and string table."
  },
  2: {
    label: "CODEVIEW",
    description: "Visual C++ debug information such as RSDS / PDB pointers."
  },
  3: {
    label: "FPO",
    description: "Frame-pointer omission metadata for nonstandard stack frames."
  },
  4: { label: "MISC", description: "Legacy location of a DBG file." },
  5: { label: "EXCEPTION", description: "Copy of the .pdata exception data." },
  6: { label: "FIXUP", description: "Reserved FIXUP debug type." },
  7: {
    label: "OMAP_TO_SRC",
    description: "Mapping from an RVA in the image to an RVA in the source image."
  },
  8: {
    label: "OMAP_FROM_SRC",
    description: "Mapping from an RVA in the source image to an RVA in the image."
  },
  9: { label: "BORLAND", description: "Reserved for Borland." },
  10: { label: "RESERVED10", description: "Reserved IMAGE_DEBUG_TYPE_RESERVED10 debug type." },
  11: { label: "CLSID", description: "Reserved CLSID debug type." },
  12: {
    label: "VC_FEATURE",
    description: "Visual C++ feature metadata emitted by the toolchain."
  },
  13: {
    label: "POGO",
    description: "Profile-guided optimization metadata emitted by the linker."
  },
  14: {
    label: "ILTCG",
    description: "Link-time code generation metadata emitted by the toolchain."
  },
  15: { label: "MPX", description: "Intel MPX metadata emitted by the toolchain." },
  16: { label: "REPRO", description: "PE determinism or reproducibility metadata." },
  17: {
    label: "EMBEDDED DEBUG",
    description: "Debugging information embedded in the PE file at PointerToRawData."
  },
  19: {
    label: "SYMBOL HASH",
    description: "Crypto hash of the symbol file content used to build the PE/COFF file."
  },
  20: {
    label: "EX_DLLCHARACTERISTICS",
    description: "Extended DLL characteristics bits beyond the optional-header field."
  }
};

const renderChip = (label: string, description: string): string =>
  `<span class="opt sel" title="${safe(description)}">${safe(label)}</span>`;

const renderCountedChips = (chips: CountedChip[]): string =>
  `<div class="optionsRow">${chips
    .map(chip =>
      renderChip(
        chip.count === 1 ? chip.label : `${chip.label} x${chip.count}`,
        chip.description
      )
    )
    .join("")}</div>`;

const getDebugTypeInfo = (type: number): DebugTypeInfo =>
  DEBUG_TYPE_INFOS[type] ?? {
    label: `TYPE_${type}`,
    description: `Undocumented or unsupported IMAGE_DEBUG_DIRECTORY.Type ${hex(type, 8)}.`
  };

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

const countByLabel = <T extends { label: string; description: string }>(
  items: T[]
): CountedChip[] => {
  const counts = new Map<string, CountedChip>();
  for (const item of items) {
    const previous = counts.get(item.label);
    counts.set(item.label, {
      count: (previous?.count ?? 0) + 1,
      label: item.label,
      description: item.description
    });
  }
  return [...counts.values()];
};

const renderEntryType = (entry: PeDebugDirectoryEntry): string => {
  const typeInfo = getDebugTypeInfo(entry.type >>> 0);
  return `${renderChip(typeInfo.label, typeInfo.description)}<div class="valueHint">${hex(entry.type, 8)}</div>`;
};

const renderEntryStorage = (
  pe: PeWindowsParseResult,
  entry: PeDebugDirectoryEntry
): string => {
  const storage = getDebugStorageInfo(pe, entry);
  return renderChip(storage.label, storage.description);
};

const renderEntryDetails = (entry: PeDebugDirectoryEntry): string => {
  if (entry.codeView) return `RSDS ${safe(entry.codeView.path || "(no path)")}`;
  return safe(getDebugTypeInfo(entry.type >>> 0).description);
};

const renderCodeViewSummary = (debug: PeDebugSection, out: string[]): void => {
  if (!debug.entry) return;
  out.push(`<dl>`);
  out.push(dd("CodeView", "RSDS", "CodeView debug directory entry with RSDS signature."));
  out.push(dd("GUID", (debug.entry.guid || "").toUpperCase(), "PDB signature GUID used to match the correct PDB file."));
  out.push(dd("Age", String(debug.entry.age), "PDB age; increments on certain rebuilds."));
  out.push(dd("Path", debug.entry.path, "Path to the PDB as recorded at link time; it can be absolute."));
  out.push(`</dl>`);
};

const renderEntrySummary = (
  pe: PeWindowsParseResult,
  debug: PeDebugSection,
  out: string[]
): void => {
  if (!debug.entries?.length) return;
  out.push(`<dl>`);
  out.push(dd("Directory entries", String(debug.entries.length), "Number of IMAGE_DEBUG_DIRECTORY records."));
  out.push(
    dd(
      "Types present",
      renderCountedChips(countByLabel(debug.entries.map(entry => getDebugTypeInfo(entry.type >>> 0))))
    )
  );
  out.push(dd(
    "Storage",
    renderCountedChips(countByLabel(debug.entries.map(entry => getDebugStorageInfo(pe, entry)))),
    "Mapped debug is section-backed with a non-zero RVA; unmapped debug is raw file data outside section coverage."
  ));
  out.push(`</dl>`);
};

export function renderDebug(pe: PeWindowsParseResult, out: string[]): void {
  if (!pe.debug) return;
  out.push(`<section><h4 style="margin:0 0 .5rem 0;font-size:.9rem">Debug directory</h4>`);
  out.push(
    `<div class="smallNote">IMAGE_DEBUG_DIRECTORY entries can point to different debug formats. ` +
      `The storage chip shows whether the payload is mapped into the image or lives only in raw file layout.</div>`
  );
  renderCodeViewSummary(pe.debug, out);
  renderEntrySummary(pe, pe.debug, out);
  if (pe.debug.entries?.length) {
    out.push(
      `<details><summary style="cursor:pointer;padding:.25rem .5rem;border:1px solid var(--border2);border-radius:6px;background:var(--chip-bg)">Show debug directory entries (${pe.debug.entries.length})</summary>`
    );
    out.push(
      `<table class="table" style="margin-top:.35rem"><thead><tr><th>#</th><th>Type</th><th>Storage</th><th>Size</th><th>Raw RVA</th><th>Raw file ptr</th><th>Details</th></tr></thead><tbody>`
    );
    pe.debug.entries.forEach((entry, index) => {
      out.push(
        `<tr><td>${index + 1}</td><td>${renderEntryType(entry)}</td><td>${renderEntryStorage(pe, entry)}</td><td>${humanSize(entry.sizeOfData)}</td><td>${hex(entry.addressOfRawData, 8)}</td><td>${hex(entry.pointerToRawData, 8)}</td><td>${renderEntryDetails(entry)}</td></tr>`
      );
    });
    out.push(`</tbody></table></details>`);
  }
  if (pe.debug.warning) out.push(`<div class="smallNote">${safe(pe.debug.warning)}</div>`);
  out.push(`</section>`);
}
