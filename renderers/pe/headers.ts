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
  DLL_FLAGS,
  formatSectionCharacteristicFlags
} from "../../analyzers/pe/constants.js";
import {
  type PeParseResult
} from "../../analyzers/pe/index.js";
import {
  PE32_OPTIONAL_HEADER_MAGIC,
  PE32_PLUS_OPTIONAL_HEADER_MAGIC,
  ROM_OPTIONAL_HEADER_MAGIC
} from "../../analyzers/pe/optional-header/magic.js";
import { peSectionNameOffset, peSectionNameValue } from "../../analyzers/pe/sections/name.js";
import {
  formatBigByteSize,
  formatPointerHex,
  formatWordListHex,
  knownSectionName,
  linkerVersionHint,
  winVersionName
} from "./header-format.js";
import { renderCoffTailSummary } from "./coff-tail-summary.js";
import { renderDosHeader } from "./dos-header.js";
import { renderMachineRows } from "./machine-rows.js";
import { renderPeSectionEnd, renderPeSectionStart } from "./collapsible-section.js";

const DATA_DIRECTORY_MEANINGS: Record<string, string> = {
  EXPORT: "Function addresses and names exported by the image.",
  IMPORT: "Modules and symbols that this image depends on at load time.",
  RESOURCE: "Version, icons, dialogs, manifests, and other embedded data.",
  EXCEPTION: "Unwind info for x64 structured exception handling.",
  SECURITY: "WIN_CERTIFICATE / Authenticode signatures, stored outside mapped image.",
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

const renderDataDirectoryStatus = (present: boolean): string =>
  `<span class="peDataDirectoryStatus peDataDirectoryStatus--${present ? "present" : "absent"}" ` +
  `aria-label="${present ? "Present" : "Absent"}" title="${present ? "Present" : "Absent"}"></span>`;

const renderDataDirectorySize = (size: number): string =>
  `<span title="${size} bytes">${humanSize(size).replace(` (${size} bytes)`, "")}</span>`;

const renderPeFormatNote = (out: string[]): void => {
  out.push(
    `<section><div class="smallNote">Portable Executable (PE) / COFF is the executable and object-file format used by Windows toolchains.</div></section>`
  );
};

const PE_SUBTYPE_LABELS: Record<string, string> = {
  "winmd": "Windows Metadata (WinMD)",
  "clr-native-image": "CLR native image"
};

const formatPeSubtype = (pe: PeParseResult): string =>
  pe.subtype ? PE_SUBTYPE_LABELS[pe.subtype] ?? pe.subtype : "-";

const renderDataDirectories = (pe: PeParseResult, out: string[]): void => {
  if (!pe.dirs?.length) return;
  const presentCount = pe.dirs.filter(
    directory => directory.rva !== 0 || directory.size !== 0
  ).length;
  out.push(
    renderPeSectionStart(
      "Data directories",
      `${presentCount} present, ${pe.dirs.length} entr${pe.dirs.length === 1 ? "y" : "ies"}`
    )
  );
  out.push(
    `<div class="tableWrap"><table class="table peDataDirectoryTable">` +
    `<thead><tr>` +
    `<th class="peDataDirectoryTable__status" aria-label="Status"></th>` +
    `<th class="peDataDirectoryTable__index">#</th>` +
    `<th class="peDataDirectoryTable__directory">Directory</th>` +
    `<th class="peDataDirectoryTable__rva">RVA</th>` +
    `<th class="peDataDirectoryTable__size">Size</th>` +
    `<th class="peDataDirectoryTable__meaning">Meaning</th>` +
    `</tr></thead><tbody>`
  );
  pe.dirs.forEach(directory => {
    const present = directory.rva !== 0 || directory.size !== 0;
    const meaning = dataDirectoryMeaning(directory.name);
    out.push(
      `<tr class="peDataDirectoryTable__row${
        present ? "" : " peDataDirectoryTable__row--absent"
      }">` +
      `<td class="peDataDirectoryTable__status" data-sort-value="${present ? "1" : "0"}">` +
      `${renderDataDirectoryStatus(present)}</td>` +
      `<td class="peNumeric peDataDirectoryTable__index" data-sort-value="${directory.index ?? ""}">` +
      `${directory.index == null ? "-" : directory.index}</td>` +
      `<th scope="row" class="peDataDirectoryTable__directory" ` +
      `data-sort-value="${escapeHtml(directory.name)}">${escapeHtml(directory.name)}</th>` +
      `<td class="peNumeric peDataDirectoryTable__rva" data-sort-value="${directory.rva}">` +
      `${hex(directory.rva, 8)}</td>` +
      `<td class="peNumeric peDataDirectoryTable__size peDataDirectorySize" ` +
      `data-sort-value="${directory.size}">` +
      `${renderDataDirectorySize(directory.size)}</td>` +
      `<td class="smallNote peDataDirectoryTable__meaning" style="margin:0;font-family:inherit" ` +
      `data-sort-value="${meaning}">${meaning}</td></tr>`
    );
  });
  out.push(`</tbody></table></div>`);
  out.push(renderPeSectionEnd());
};

const renderSections = (pe: PeParseResult, out: string[]): void => {
  const sections = pe.sections || [];
  if (!sections.length) return;
  out.push(
    renderPeSectionStart(
      "Section headers",
      `${sections.length} section${sections.length === 1 ? "" : "s"}`
    )
  );
  out.push(
    `<table class="table" style="margin-top:.35rem"><thead><tr><th>Name</th><th>VirtualSize</th><th>RVA</th><th>RawSize</th><th>FilePtr</th><th>Entropy</th><th>Flags</th></tr></thead><tbody>`
  );
  sections.forEach(section => {
    const flags = formatSectionCharacteristicFlags(section.characteristics);
    const sectionName = peSectionNameValue(section.name);
    const coffStringTableOffset = peSectionNameOffset(section.name);
    const hint = knownSectionName(sectionName);
    const baseNameCell = hint
      ? `<span title="${hint}"><b>${escapeHtml(sectionName || "(unnamed)")}</b></span>`
      : `<span title="User-defined">${escapeHtml(sectionName || "(unnamed)")}</span>`;
    const nameCell =
      coffStringTableOffset != null && sectionName !== `/${coffStringTableOffset}`
        ? `${baseNameCell}<div class="smallNote dim">COFF name /${coffStringTableOffset}</div>`
        : baseNameCell;
    out.push(`<tr>
        <td>${nameCell}</td>
        <td>${humanSize(section.virtualSize)}</td>
        <td>${hex(section.virtualAddress, 8)}</td>
        <td>${humanSize(section.sizeOfRawData)}</td>
        <td>${hex(section.pointerToRawData, 8)}</td>
        <td title="Shannon entropy (0..8 bits/byte). Near 0 means very simple or empty, near 8 means very mixed data (often compressed or encrypted).">${(section.entropy ?? 0).toFixed(2)}</td>
        <td>${flags.join(" &middot; ")}</td>
      </tr>`);
  });
  out.push(`</tbody></table>`);
  out.push(renderPeSectionEnd());
};

const renderInlineHeaderTitle = (title: string): string =>
  `<h4 style="margin:0 0 .5rem 0;font-size:.9rem">${title}</h4>`;

export function renderHeaders(pe: PeParseResult, out: string[]): void {
  renderPeFormatNote(out);
  renderDosHeader(pe, out);

  out.push(renderPeSectionStart("PE/COFF headers"));
  out.push(renderInlineHeaderTitle("PE signature"));
  out.push(`<dl>`);
  out.push(renderDefinitionRow("Signature", "PE", "The PE\\0\\0 signature precedes the COFF file header and identifies the image as PE/COFF."));
  out.push(renderDefinitionRow("Subtype", formatPeSubtype(pe), "Derived from specification-defined PE metadata when present."));
  out.push(`</dl>`);
  out.push(renderInlineHeaderTitle("COFF file header"));
  out.push(`<dl>`);
  renderMachineRows(pe, out);
  out.push(renderDefinitionRow("NumberOfSections", `${pe.coff.NumberOfSections}`, "Number of section headers that immediately follow the optional header."));
  out.push(renderDefinitionRow("TimeDateStamp", isoOrDash(pe.coff.TimeDateStamp), "Link time as Unix epoch. Toolchains sometimes set this to reproducible values."));
  out.push(renderDefinitionRow("PointerToSymbolTable", hex(pe.coff.PointerToSymbolTable, 8), "COFF symbol table pointer (deprecated, usually 0)."));
  out.push(renderDefinitionRow("NumberOfSymbols", String(pe.coff.NumberOfSymbols), "COFF symbol count (deprecated)."));
  out.push(renderDefinitionRow("SizeOfOptionalHeader", `${pe.coff.SizeOfOptionalHeader} bytes`, "Size of the optional header (standard + Windows-specific)."));
  out.push(renderDefinitionRow("Characteristics", renderFlagChips(pe.coff.Characteristics, CHAR_FLAGS), "Flags describing image traits (DLL, system file, etc.)."));
  out.push(`</dl>`);

  const oh = pe.opt;
  const entrySectionInfo = pe.entrySection
    ? `Usually points into section ${pe.entrySection.name || "(unnamed)"} (index ${pe.entrySection.index}).`
    : "Should point into one of the mapped code sections.";
  out.push(renderInlineHeaderTitle("Optional header"));
  out.push(`<dl>`);
  if (!oh) {
    out.push(`</dl>`);
    out.push(`<div class="smallNote">Optional header fields are unavailable because the file did not declare a recognized PE32, PE32+, or ROM optional header.</div>`);
    out.push(renderPeSectionEnd());
    renderDataDirectories(pe, out);
    renderSections(pe, out);
    const coffTailSummary = renderCoffTailSummary(pe);
    if (coffTailSummary) out.push(coffTailSummary);
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
      "Linker that produced this image (MSVC or lld-link version family)."
    )
  );
  out.push(renderDefinitionRow("SizeOfCode", humanSize(oh.SizeOfCode), "Size of code section bytes."));
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
        : "RVA of entry point. Zero for DLLs without a preferred entry."
    )
  );
  out.push(renderDefinitionRow("EntrySection", pe.entrySection ? escapeHtml(pe.entrySection.name || "(unnamed)") : "-", entrySectionInfo));
  if (oh.Magic === ROM_OPTIONAL_HEADER_MAGIC) {
    out.push(renderDefinitionRow("BaseOfCode", hex(oh.BaseOfCode, 8), "Base address of code within the ROM image."));
    out.push(renderDefinitionRow("BaseOfData", hex(oh.BaseOfData, 8), "Base address of initialized data within the ROM image."));
    out.push(renderDefinitionRow("BaseOfBss", hex(oh.rom.BaseOfBss, 8), "Base address of uninitialized data within the ROM image."));
    out.push(renderDefinitionRow("GprMask", hex(oh.rom.GprMask, 8), "General-purpose register mask recorded by the ROM toolchain."));
    out.push(renderDefinitionRow("CprMask", formatWordListHex(oh.rom.CprMask), "Coprocessor register masks recorded by the ROM toolchain."));
    out.push(renderDefinitionRow("GpValue", hex(oh.rom.GpValue, 8), "Global-pointer seed value recorded in IMAGE_ROM_OPTIONAL_HEADER."));
    out.push(`</dl>`);
    out.push(`<div class="smallNote">ROM optional headers stop here: Windows-only fields such as ImageBase, SectionAlignment, Subsystem, CheckSum, stack/heap sizes, and the PE data-directory array are not part of IMAGE_ROM_OPTIONAL_HEADER.</div>`);
    out.push(renderPeSectionEnd());
  } else {
    const pointerWidth = oh.Magic === PE32_PLUS_OPTIONAL_HEADER_MAGIC ? 16 : 8;
    out.push(renderDefinitionRow("ImageBase", formatPointerHex(oh.ImageBase, pointerWidth), "Preferred load address."));
    out.push(renderDefinitionRow("SectionAlignment", humanSize(oh.SectionAlignment), "Alignment of sections in memory."));
    out.push(renderDefinitionRow("FileAlignment", humanSize(oh.FileAlignment), "Alignment of sections in the file."));
    out.push(renderDefinitionRow("OperatingSystemVersion", winVersionName(oh.OSVersionMajor, oh.OSVersionMinor), "Minimum required OS version."));
    out.push(renderDefinitionRow("ImageVersion", `${oh.ImageVersionMajor}.${oh.ImageVersionMinor}`, "Image version (informational)."));
    out.push(renderDefinitionRow("SubsystemVersion", `${oh.SubsystemVersionMajor}.${oh.SubsystemVersionMinor}`, "Minimum subsystem version."));
    out.push(renderDefinitionRow("Subsystem", renderOptionChips(oh.Subsystem, SUBSYSTEMS), "Required subsystem (GUI, CUI, etc.)."));
    out.push(renderDefinitionRow("DllCharacteristics", renderFlagChips(oh.DllCharacteristics, DLL_FLAGS), "DLL characteristics (ASLR, DEP, etc.)."));
    out.push(renderDefinitionRow("SizeOfImage", humanSize(oh.SizeOfImage), "Size of image in memory, including all headers and sections."));
    out.push(renderDefinitionRow("SizeOfHeaders", humanSize(oh.SizeOfHeaders), "Combined size of DOS stub, PE header, and section headers."));
    const checksumHtml = [
      `<div style="display:flex;flex-direction:column;gap:.35rem">`,
      `<div class="mono">${hex(oh.CheckSum, 8)}</div>`,
      `<div class="smallNote">Validation: <span id="peChecksumStatus">Not validated yet.</span></div>`,
      `<div class="smallNote">Computed: <span class="mono" id="peChecksumComputed">-</span></div>`,
      `<div><button type="button" class="actionButton" id="peChecksumValidateButton">Validate CheckSum</button></div>`,
      `</div>`
    ].join("");
    out.push(renderDefinitionRow("CheckSum", checksumHtml, "Image checksum (used by some system components)."));
    out.push(renderDefinitionRow("SizeOfStackReserve", formatBigByteSize(oh.SizeOfStackReserve), "Stack reservation size."));
    out.push(renderDefinitionRow("SizeOfStackCommit", formatBigByteSize(oh.SizeOfStackCommit), "Stack commit size."));
    out.push(renderDefinitionRow("SizeOfHeapReserve", formatBigByteSize(oh.SizeOfHeapReserve), "Heap reservation size."));
    out.push(renderDefinitionRow("SizeOfHeapCommit", formatBigByteSize(oh.SizeOfHeapCommit), "Heap commit size."));
    out.push(`</dl>`);
    out.push(renderPeSectionEnd());
  }
  renderDataDirectories(pe, out);
  renderSections(pe, out);
  const coffTailSummary = renderCoffTailSummary(pe);
  if (coffTailSummary) out.push(coffTailSummary);
}
