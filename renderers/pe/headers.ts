"use strict";
import { humanSize, hex, isoOrDash } from "../../binary-utils.js";
import {
  renderDefinitionRow,
  renderOptionChips,
  renderFlagChips,
  escapeHtml
} from "../../html-utils.js";
import {
  SUBSYSTEMS,
  CHAR_FLAGS,
  DLL_FLAGS
} from "../../analyzers/pe/constants.js";
import { isPeWindowsParseResult, type PeParseResult } from "../../analyzers/pe/index.js";
import type { PeDataDirectory } from "../../analyzers/pe/types.js";
import { IMAGE_DEBUG_TYPE_REPRO } from "../../analyzers/pe/debug/types.js";
import { peDirectoryCoverageIssue } from "../../analyzers/pe/directories/file-coverage.js";
import { hasPeResourceDirectoryDetails } from "./directory-details.js";
import { renderPeDiagnostics } from "./diagnostics.js";
import { CRINKLER_SHORT_OPTIONAL_HEADER_BYTES } from
  "../../analyzers/pe/packers/crinkler-layout.js";
import {
  PE32_OPTIONAL_HEADER_MAGIC,
  PE32_PLUS_OPTIONAL_HEADER_MAGIC,
  ROM_OPTIONAL_HEADER_MAGIC
} from "../../analyzers/pe/optional-header/magic.js";
import {
  formatBigByteSize,
  formatPointerHex,
  formatWordListHex
} from "./header-format.js";
import { renderHeaderVersions } from "./header-versions.js";
import { linkerVersionHint } from "./linker-version.js";
import { renderCoffTailSummary } from "./coff-tail-summary.js";
import { renderDosHeader } from "./dos-header.js";
import { renderMachineRows } from "./machine-rows.js";
import { renderPeSectionEnd, renderPeSectionStart } from "./collapsible-section.js";
import { renderSections } from "./section-headers.js";

const DATA_DIRECTORY_MEANINGS: Record<string, string> = {
  EXPORT: "Function addresses and names exported by the image.",
  IMPORT: "Modules and symbols that this image depends on at load time.",
  RESOURCE: "Version, icons, dialogs, manifests, and other embedded data.",
  EXCEPTION: "Architecture-specific function records used for exception handling and unwinding.",
  SECURITY: "Embedded WIN_CERTIFICATE records stored outside the mapped image.",
  BASERELOC: "Fixups applied when image is not loaded at preferred base.",
  DEBUG: "CodeView/RSDS pointers to PDBs and other debug records.",
  ARCHITECTURE: "Reserved slot; should be zero by the PE specification.",
  GLOBALPTR: "Value to store in the global pointer register; Size should be zero.",
  TLS: "Per-thread data and optional TLS callbacks.",
  LOAD_CONFIG: "Security hardening structures: CFG, SEH tables, GS cookie.",
  BOUND_IMPORT: "Prebinding metadata for imported modules, when present.",
  IAT: "Resolved addresses patched by the loader at runtime.",
  DELAY_IMPORT: "Imports resolved on first use by the delay-load helper.",
  CLR_RUNTIME: ".NET/CLR header for managed assemblies.",
  RESERVED: "Reserved slot."
};

const dataDirectoryMeaning = (name: string): string =>
  DATA_DIRECTORY_MEANINGS[name] || "Reserved or producer-specific directory slot.";

const renderDataDirectoryStatus = (
  kind: "absent" | "present" | "unverified", label: string
): string =>
  `<span class="peDataDirectoryStatus peDataDirectoryStatus--${kind}" ` +
  `role="img" aria-label="${escapeHtml(label)}" title="${escapeHtml(label)}"></span>`;

const renderDataDirectorySize = (size: number): string =>
  `<span title="${size} bytes">${humanSize(size).replace(` (${size} bytes)`, "")}</span>`;

const collectUnreadableDirectoryWarnings = (pe: PeParseResult): Map<
  string, { title: string; issues: string[] }
> => {
  const warnings = new Map<string, { title: string; issues: string[] }>();
  if (!isPeWindowsParseResult(pe)) return warnings;
  if (!pe.imports.entries.length && pe.imports.warning) {
    warnings.set("IMPORT", { title: "Import warnings", issues: [pe.imports.warning] });
  }
  if (pe.exports?.headerRead === false && pe.exports.issues?.length) {
    warnings.set("EXPORT", { title: "Export warnings", issues: pe.exports.issues });
  }
  if (pe.resources?.issues?.length && !hasPeResourceDirectoryDetails(pe.resources)) {
    warnings.set("RESOURCE", { title: "Resource warnings", issues: pe.resources.issues });
  }
  return warnings;
};

const renderDataDirectoryRow = (
  directory: PeDataDirectory, pe: PeParseResult, warning: string | undefined
): string => {
  const present = directory.rva !== 0 || directory.size !== 0;
  const issue = present && isPeWindowsParseResult(pe)
    ? peDirectoryCoverageIssue(directory, pe) ?? warning : null;
  const meaning = dataDirectoryMeaning(directory.name);
  const addressKind = directory.name === "SECURITY" ? "File offset" : "RVA";
  return `<tr class="peDataDirectoryTable__row${
    present ? "" : " peDataDirectoryTable__row--absent"
  }">` +
    `<td class="peDataDirectoryTable__status" data-sort-value="${issue ? 2 : Number(present)}">` +
    `${issue
      ? renderDataDirectoryStatus("unverified", `Unverified: ${issue}`)
      : renderDataDirectoryStatus(present ? "present" : "absent", present ? "Declared" : "Absent")
    }</td>` +
    `<td class="peNumeric peDataDirectoryTable__index" data-sort-value="${directory.index ?? ""}">` +
    `${directory.index == null ? "-" : directory.index}</td>` +
    `<th scope="row" class="peDataDirectoryTable__directory" ` +
    `data-sort-value="${escapeHtml(directory.name)}">${escapeHtml(directory.name)}</th>` +
    `<td class="peNumeric peDataDirectoryTable__rva" data-sort-value="${directory.rva}">` +
    `${hex(directory.rva, 8)} <span class="smallNote">${addressKind}</span></td>` +
    `<td class="peNumeric peDataDirectoryTable__size peDataDirectorySize" ` +
    `data-sort-value="${directory.size}">` +
    `${renderDataDirectorySize(directory.size)}</td>` +
    `<td class="smallNote peDataDirectoryTable__meaning" style="margin:0;font-family:inherit" ` +
    `data-sort-value="${meaning}">${meaning}</td></tr>`;
};

const renderDataDirectories = (pe: PeParseResult, out: string[]): void => {
  if (!pe.dirs?.length) return;
  const presentCount = pe.dirs.filter(
    directory => directory.rva !== 0 || directory.size !== 0
  ).length;
  out.push(
    renderPeSectionStart(
      "Data directories",
      `${presentCount} declared, ${pe.dirs.length} entr${pe.dirs.length === 1 ? "y" : "ies"}`
    )
  );
  out.push(
    `<div class="tableWrap"><table class="table peDataDirectoryTable">` +
    `<thead><tr>` +
    `<th class="peDataDirectoryTable__status" aria-label="Status"></th>` +
    `<th class="peDataDirectoryTable__index">#</th>` +
    `<th class="peDataDirectoryTable__directory">Directory</th>` +
    `<th class="peDataDirectoryTable__rva">Address</th>` +
    `<th class="peDataDirectoryTable__size">Size</th>` +
    `<th class="peDataDirectoryTable__meaning">Meaning</th>` +
    `</tr></thead><tbody>`
  );
  const warnings = collectUnreadableDirectoryWarnings(pe);
  for (const directory of pe.dirs) {
    out.push(renderDataDirectoryRow(directory, pe, warnings.get(directory.name)?.issues[0]));
  }
  out.push(`</tbody></table></div>`);
  for (const { title, issues } of warnings.values()) out.push(renderPeDiagnostics(title, issues));
  out.push(renderPeSectionEnd());
};

const renderInlineHeaderTitle = (title: string): string =>
  `<h4 class="peHeaderTitle">${title}</h4>`;

const renderHeadersTail = (pe: PeParseResult, out: string[]): void => {
  renderDataDirectories(pe, out);
  renderSections(pe, out);
  const coffTailSummary = renderCoffTailSummary(pe);
  if (coffTailSummary) out.push(coffTailSummary);
};

const renderMissingOptionalHeader = (pe: PeParseResult, out: string[]): void => {
  out.push(`</dl>`);
  out.push(
    `<div class="smallNote">Optional header fields are unavailable because the file did not ` +
      `declare a recognized PE32, PE32+, or ROM optional header.</div>`
  );
  out.push(renderPeSectionEnd());
  renderHeadersTail(pe, out);
};

const renderRomOptionalHeader = (pe: PeParseResult, out: string[]): void => {
  if (!pe.opt || pe.opt.Magic !== ROM_OPTIONAL_HEADER_MAGIC) return;
  out.push(renderDefinitionRow("BaseOfCode", hex(pe.opt.BaseOfCode, 8), "Base address of code within the ROM image."));
  out.push(renderDefinitionRow("BaseOfData", hex(pe.opt.BaseOfData, 8), "Base address of initialized data within the ROM image."));
  out.push(renderDefinitionRow("BaseOfBss", hex(pe.opt.rom.BaseOfBss, 8), "Base address of uninitialized data within the ROM image."));
  out.push(renderDefinitionRow("GprMask", hex(pe.opt.rom.GprMask, 8), "General-purpose register mask recorded by the ROM toolchain."));
  out.push(renderDefinitionRow("CprMask", formatWordListHex(pe.opt.rom.CprMask), "Coprocessor register masks recorded by the ROM toolchain."));
  out.push(renderDefinitionRow("GpValue", hex(pe.opt.rom.GpValue, 8), "Global-pointer seed value recorded in IMAGE_ROM_OPTIONAL_HEADER."));
  out.push(`</dl>`);
  out.push(`<div class="smallNote">ROM optional headers stop here: Windows-only fields such as ImageBase, SectionAlignment, Subsystem, CheckSum, stack/heap sizes, and the PE data-directory array are not part of IMAGE_ROM_OPTIONAL_HEADER.</div>`);
  out.push(renderPeSectionEnd());
};

const renderChecksumHtml = (checkSum: number): string => [
  `<div style="display:flex;flex-direction:column;gap:.35rem">`,
  `<div class="mono">${hex(checkSum, 8)}</div>`,
  `<div class="smallNote">Validation: <span id="peChecksumStatus">Not validated yet.</span></div>`,
  `<div class="smallNote">Computed: <span class="mono" id="peChecksumComputed">-</span></div>`,
  `<div><button type="button" class="actionButton" id="peChecksumValidateButton">Validate CheckSum</button></div>`,
  `</div>`
].join("");

const renderCoffTimestamp = (pe: PeParseResult): string => {
  const raw = hex(pe.coff.TimeDateStamp, 8);
  // .NET PE/COFF Specification Addendum, "Deterministic PE/COFF File".
  // https://github.com/dotnet/runtime/blob/main/docs/design/specs/PE-COFF.md
  if (isPeWindowsParseResult(pe) &&
      pe.debug?.entries?.some(entry => entry.type === IMAGE_DEBUG_TYPE_REPRO)) {
    return renderDefinitionRow("TimeDateStamp", raw,
      "The REPRO debug marker indicates a reproducible build. Read this value as a build stamp.");
  }
  // Microsoft PE Format, "General Concepts", defines both values as no timestamp.
  if (pe.coff.TimeDateStamp === 0 || pe.coff.TimeDateStamp === 0xffffffff) {
    return renderDefinitionRow("TimeDateStamp", `${raw} (no timestamp)`);
  }
  return renderDefinitionRow("TimeDateStamp", `${raw} (${isoOrDash(pe.coff.TimeDateStamp)})`,
    "Raw COFF stamp and its interpretation as Unix seconds. Some toolchains store a build stamp.");
};

export function renderHeaders(pe: PeParseResult, out: string[]): void {
  renderDosHeader(pe, out);

  out.push(renderPeSectionStart("PE/COFF headers"));
  out.push(renderInlineHeaderTitle("PE signature"));
  out.push(`<dl>`);
  out.push(renderDefinitionRow("Signature", "PE", "The PE\\0\\0 signature precedes the COFF file header and identifies the image as PE/COFF."));
  out.push(`</dl>`);
  out.push(renderInlineHeaderTitle("COFF file header"));
  out.push(`<dl>`);
  renderMachineRows(pe, out);
  out.push(renderDefinitionRow("NumberOfSections", `${pe.coff.NumberOfSections}`, "Number of section headers that immediately follow the optional header."));
  out.push(renderCoffTimestamp(pe));
  out.push(renderDefinitionRow("PointerToSymbolTable", hex(pe.coff.PointerToSymbolTable, 8), "COFF symbol table pointer (deprecated, usually 0)."));
  out.push(renderDefinitionRow("NumberOfSymbols", String(pe.coff.NumberOfSymbols), "COFF symbol count (deprecated)."));
  out.push(renderDefinitionRow("SizeOfOptionalHeader", `${pe.coff.SizeOfOptionalHeader} bytes`, "Size of the optional header (standard + Windows-specific)."));
  out.push(renderDefinitionRow("Characteristics", renderFlagChips(pe.coff.Characteristics, CHAR_FLAGS), "Flags describing COFF file traits."));
  out.push(`</dl>`);

  const oh = pe.opt;
  const entrySectionInfo = pe.entrySection
    ? `Entry-point RVA falls in section ${pe.entrySection.name || "(unnamed)"} ` +
      `(index ${pe.entrySection.index}).`
    : "Should point into one of the mapped code sections.";
  out.push(renderInlineHeaderTitle("Optional header"));
  out.push(`<dl>`);
  if (!oh) {
    renderMissingOptionalHeader(pe, out);
    return;
  }
  out.push(
    renderDefinitionRow(
      "Magic",
      renderOptionChips(oh.Magic, [[PE32_OPTIONAL_HEADER_MAGIC, "PE32"], [PE32_PLUS_OPTIONAL_HEADER_MAGIC, "PE32+"], [ROM_OPTIONAL_HEADER_MAGIC, "ROM"]]),
      "Identifies PE32 (32-bit), PE32+ (64-bit), or IMAGE_ROM_OPTIONAL_HEADER."
    )
  );
  out.push(
    renderDefinitionRow(
      "LinkerVersion",
      linkerVersionHint(oh.LinkerMajor, oh.LinkerMinor),
      "Producer-written linker version. Names are possible matches; the field does not identify a tool uniquely."
    )
  );
  out.push(renderDefinitionRow("SizeOfCode", humanSize(oh.SizeOfCode), "Size of code section bytes."));
  if (pe.subtype === "crinkler" && pe.coff.SizeOfOptionalHeader === CRINKLER_SHORT_OPTIONAL_HEADER_BYTES) {
    out.push("</dl>",
      '<p class="smallNote">The declared optional header ends here.</p>', renderPeSectionEnd());
    renderHeadersTail(pe, out);
    return;
  }
  out.push(
    renderDefinitionRow(
      "SizeOfInitializedData",
      humanSize(oh.SizeOfInitializedData),
      "Size of initialized data section bytes."
    )
  );
  out.push(
    renderDefinitionRow(
      "SizeOfUninitializedData",
      humanSize(oh.SizeOfUninitializedData),
      "Size of uninitialized data bytes (BSS)."
    )
  );
  out.push(
    renderDefinitionRow(
      "AddressOfEntryPoint",
      hex(oh.AddressOfEntryPoint, 8),
      oh.Magic === ROM_OPTIONAL_HEADER_MAGIC
        ? "Entry-point address stored in IMAGE_ROM_OPTIONAL_HEADER."
        : "RVA of the image entry point. Zero means the image has no entry point."
    )
  );
  out.push(renderDefinitionRow("EntrySection", pe.entrySection ? escapeHtml(pe.entrySection.name || "(unnamed)") : "-", entrySectionInfo));
  if (oh.Magic === ROM_OPTIONAL_HEADER_MAGIC) {
    renderRomOptionalHeader(pe, out);
  } else {
    const pointerWidth = oh.Magic === PE32_PLUS_OPTIONAL_HEADER_MAGIC ? 16 : 8;
    out.push(renderDefinitionRow("ImageBase", formatPointerHex(oh.ImageBase, pointerWidth), "Preferred load address."));
    out.push(renderDefinitionRow("SectionAlignment", humanSize(oh.SectionAlignment), "Alignment of sections in memory."));
    out.push(renderDefinitionRow("FileAlignment", humanSize(oh.FileAlignment), "Alignment of sections in the file."));
    out.push(renderHeaderVersions(oh));
    out.push(renderDefinitionRow("Subsystem", renderOptionChips(oh.Subsystem, SUBSYSTEMS), "Required subsystem (GUI, CUI, etc.)."));
    out.push(renderDefinitionRow("DllCharacteristics", renderFlagChips(oh.DllCharacteristics, DLL_FLAGS), "DLL characteristics (ASLR, DEP, etc.)."));
    out.push(renderDefinitionRow("SizeOfImage", humanSize(oh.SizeOfImage), "Size of image in memory, including all headers and sections."));
    out.push(renderDefinitionRow("SizeOfHeaders", humanSize(oh.SizeOfHeaders), "Combined size of DOS stub, PE header, and section headers."));
    out.push(renderDefinitionRow("CheckSum", renderChecksumHtml(oh.CheckSum), "Image checksum (used by some system components)."));
    out.push(renderDefinitionRow("SizeOfStackReserve", formatBigByteSize(oh.SizeOfStackReserve), "Stack reservation size."));
    out.push(renderDefinitionRow("SizeOfStackCommit", formatBigByteSize(oh.SizeOfStackCommit), "Stack commit size."));
    out.push(renderDefinitionRow("SizeOfHeapReserve", formatBigByteSize(oh.SizeOfHeapReserve), "Heap reservation size."));
    out.push(renderDefinitionRow("SizeOfHeapCommit", formatBigByteSize(oh.SizeOfHeapCommit), "Heap commit size."));
    out.push(`</dl>`);
    out.push(renderPeSectionEnd());
  }
  renderHeadersTail(pe, out);
}
