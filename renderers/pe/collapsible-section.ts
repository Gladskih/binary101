"use strict";

import { escapeHtml } from "../../html-utils.js";

const PE_SECTION_DESCRIPTIONS: Record<string, string> = {
  "Architecture directory":
    "Reserved PE data-directory slot; non-zero values are mainly useful as anomaly signals.",
  "Base relocations":
    "Relocation blocks let the loader adjust absolute addresses when the image is not loaded at its preferred base.",
  "Bound imports":
    "Optional prebinding metadata that records imported module timestamps and forwarder references.",
  "CLR / .NET":
    "Managed-code metadata used by the .NET runtime, including CLR header, metadata streams, and managed resources.",
  "Data directories":
    "Optional-header directory entries that point to higher-level PE structures such as imports, resources, TLS, and security data.",
  "Debug directory":
    "Compiler and linker debug records such as CodeView paths, PDB identifiers, POGO, and reproducibility markers.",
  "Delay-load imports":
    "Imports that are resolved on first use by a delay-load helper instead of during initial process startup.",
  "DOS header":
    "The legacy MZ header and stub at the start of a PE file; e_lfanew points to the PE signature.",
  "Exception directory":
    "Unwind and exception-handling metadata used by the OS runtime for stack walking and handler dispatch.",
  "Export directory":
    "Symbols this image exposes to other modules by name, ordinal, or forwarder string.",
  "Global pointer (GP)":
    "Machine-specific GLOBALPTR directory data for images that use GP-relative addressing.",
  "Import Address Table (IAT)":
    "Runtime thunk table that the loader patches with resolved imported function addresses.",
  "Import Address Tables (IAT)":
    "Declared and inferred import-address-table ranges, compared against import descriptors and delay-load descriptors.",
  "Import linking":
    "Cross-checks relationships between normal imports, bound imports, delay-load imports, IAT ranges, and section layout.",
  "Import table":
    "Imported DLLs and functions that the Windows loader resolves for the image.",
  "Load Config":
    "PE loader metadata for compiler and OS hardening features such as CFG, SafeSEH, GS cookies, Code Integrity hints, and dynamic relocations.",
  "Legacy COFF tail":
    "Deprecated COFF symbol and string-table data stored after mapped PE sections.",
  "Native AOT candidate":
    "Conservative evidence for .NET Native AOT style images based on PE and CLR metadata.",
  "Packaging signatures":
    "High-confidence local evidence for installers and runtime packagers embedded in this PE image.",
  "PE/COFF headers":
    "Core PE signature, COFF file header, and optional header fields that define the image layout.",
  "Resources":
    "Hierarchical resource tree containing dialogs, icons, manifests, version data, strings, and other embedded assets.",
  "Rich header":
    "Microsoft linker/toolchain fingerprint stored in the DOS stub area before the PE signature.",
  "Sanity":
    "Best-effort structural findings that cross-check headers, sections, entry point, overlay, and related metadata.",
  "Security directory":
    "WIN_CERTIFICATE records, including Authenticode signatures stored outside the mapped image.",
  "Section headers":
    "Section table entries describing named image regions, their RVAs, raw file ranges, sizes, and flags.",
  "TLS directory":
    "Thread-local-storage template and optional callbacks that the loader runs for thread and process events."
};

const renderPeSectionDescription = (title: string): string => {
  const description = PE_SECTION_DESCRIPTIONS[title];
  return description ? `<div class="smallNote">${escapeHtml(description)}</div>` : "";
};

export const renderPeSectionStart = (title: string, summary?: string, id?: string): string =>
  `<section${id ? ` id="${escapeHtml(id)}"` : ""} class="peSection">` +
  `<details class="peSectionDetails">` +
  `<summary class="peSectionSummary"><b>${escapeHtml(title)}</b>${
    summary ? ` - ${escapeHtml(summary)}` : ""
  }</summary><div class="peSectionBody">${renderPeSectionDescription(title)}`;

export const renderPeSectionEnd = (): string => "</div></details></section>";

export const renderPeSectionShell = (
  key: string,
  title: string,
  summary?: string,
  id?: string
): string =>
  `<section${id ? ` id="${escapeHtml(id)}"` : ""} class="peSection" ` +
  `data-pe-lazy-section="${escapeHtml(key)}">` +
  `<details class="peSectionDetails">` +
  `<summary class="peSectionSummary"><b>${escapeHtml(title)}</b>${
    summary ? ` - ${escapeHtml(summary)}` : ""
  }</summary><div class="peSectionBody" data-pe-lazy-section-body></div>` +
  `</details></section>`;
