"use strict";
import { humanSize, hex, isoOrDash } from "../../binary-utils.js";
import { dd, rowOpts, rowFlags, safe } from "../../html-utils.js";
import { MACHINE, SUBSYSTEMS, CHAR_FLAGS, DLL_FLAGS, SEC_FLAG_TEXTS, DD_TIPS } from "../../analyzers/pe/constants.js";
import {
  type PeParseResult
} from "../../analyzers/pe/index.js";
import {
  PE32_OPTIONAL_HEADER_MAGIC,
  PE32_PLUS_OPTIONAL_HEADER_MAGIC,
  ROM_OPTIONAL_HEADER_MAGIC
} from "../../analyzers/pe/optional-header-magic.js";
import { peSectionNameOffset, peSectionNameValue } from "../../analyzers/pe/section-name.js";
import {
  formatBigByteSize,
  formatPointerHex,
  formatWordListHex,
  knownSectionName,
  linkerVersionHint,
  winVersionName
} from "./header-format.js";
import { renderRichHeader } from "./rich-header.js";
import { renderCoffTailSummary } from "./coff-tail-summary.js";
import { renderPeSectionEnd, renderPeSectionStart } from "./collapsible-section.js";

const renderPeFormatNote = (out: string[]): void => {
  out.push(
    `<section><div class="smallNote">Portable Executable (PE) / COFF is the executable and object-file format used by Windows toolchains.</div></section>`
  );
};

const renderDataDirectories = (pe: PeParseResult, out: string[]): void => {
  if (!pe.dirs?.length) return;
  const presentCount = pe.dirs.filter(directory => directory.rva !== 0 || directory.size !== 0).length;
  out.push(
    renderPeSectionStart(
      "Data directories",
      `${presentCount} present, ${pe.dirs.length} entr${pe.dirs.length === 1 ? "y" : "ies"}`
    )
  );
  out.push(`<dl>`);
  pe.dirs.forEach(d => {
    const tip = (DD_TIPS as Record<string, string | undefined>)[d.name] || "Directory";
    out.push(
      dd(
        `[${d.index}] ${d.name}`,
        `RVA ${hex(d.rva, 8)}, Size ${humanSize(d.size)}`,
        tip
      )
    );
  });
  out.push(`</dl>`);
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
    const flags = SEC_FLAG_TEXTS.filter(([bit]) => (section.characteristics & bit) !== 0).map(([, text]) => text);
    const sectionName = peSectionNameValue(section.name);
    const coffStringTableOffset = peSectionNameOffset(section.name);
    const hint = knownSectionName(sectionName);
    const baseNameCell = hint
      ? `<span title="${safe(hint)}"><b>${safe(sectionName || "(unnamed)")}</b></span>`
      : `<span title="User-defined">${safe(sectionName || "(unnamed)")}</span>`;
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
  `<h4 style="margin:0 0 .5rem 0;font-size:.9rem">${safe(title)}</h4>`;

export function renderHeaders(pe: PeParseResult, out: string[]): void {
  renderPeFormatNote(out);

  out.push(`<section>`);
  out.push(
    `<details><summary style="cursor:pointer;padding:.35rem .6rem;border:1px solid var(--border2);border-radius:8px;background:var(--chip-bg)"><b>DOS header</b> (click to expand)</summary>`
  );
  out.push(`<div style="margin-top:.5rem"><dl>`);
  out.push(dd("e_magic", "MZ", "DOS header signature. PE files begin with a small DOS program (stub)."));
  out.push(dd("e_cblp", `${pe.dos.e_cblp} bytes last page`, "Number of bytes on last page of file (legacy)."));
  out.push(dd("e_cp", `${pe.dos.e_cp} pages`, "File size measured in 512-byte pages (legacy)."));
  out.push(dd("e_crlc", String(pe.dos.e_crlc), "Relocations count for the DOS MZ program (should be 0 for PE)."));
  out.push(dd("e_cparhdr", `${pe.dos.e_cparhdr} paragraphs (>=4)`, "Header size in 16-byte paragraphs (MZ)."));
  out.push(dd("e_minalloc", String(pe.dos.e_minalloc), "Minimum extra paragraphs needed (DOS)."));
  out.push(dd("e_maxalloc", String(pe.dos.e_maxalloc), "Maximum extra paragraphs needed (DOS)."));
  out.push(dd("e_ss", hex(pe.dos.e_ss, 4), "Initial stack segment for DOS stub (legacy)."));
  out.push(dd("e_sp", hex(pe.dos.e_sp, 4), "Initial stack pointer for DOS stub (legacy)."));
  out.push(dd("e_csum", hex(pe.dos.e_csum, 4), "Checksum for DOS program (usually 0)."));
  out.push(dd("e_ip", hex(pe.dos.e_ip, 4), "Initial instruction pointer for DOS stub."));
  out.push(dd("e_cs", hex(pe.dos.e_cs, 4), "Initial code segment for DOS stub."));
  out.push(
    dd(
      "e_lfarlc",
      hex(pe.dos.e_lfarlc, 4),
      "Offset to relocation table within DOS header (usually 0x40)."
    )
  );
  out.push(dd("e_oemid", hex(pe.dos.e_oemid, 4), "OEM identifier."));
  out.push(dd("e_oeminfo", hex(pe.dos.e_oeminfo, 4), "OEM-specific information."));
  out.push(
    dd(
      "e_lfanew",
      hex(pe.dos.e_lfanew, 8),
      `File offset to PE signature (${pe.dos.e_lfanew >= 0x80 ? "typically near end of headers" : ""}).`
    )
  );
  out.push(`</dl>`);
  const stub = pe.dos.stub;
  out.push(`<div class="smallNote">DOS stub: ${stub.kind}${stub.note ? ` - ${safe(stub.note)}` : ""}</div>`);
  if (stub.strings?.length) {
    out.push(`<div class="mono smallNote">${stub.strings.map(x => `<div>${safe(String(x))}</div>`).join("")}</div>`);
  }
  if (pe.dos.rich) {
    out.push(`<div style="margin-top:.75rem">`);
    renderRichHeader(pe.dos.rich, out);
    out.push(`</div>`);
  } else {
    out.push(
      `<div class="smallNote" style="margin-top:.5rem">Rich header: not present (no DanS/Rich signature found in DOS stub).</div>`
    );
  }
  out.push(`</div></details></section>`);

  out.push(renderPeSectionStart("PE/COFF headers"));
  out.push(renderInlineHeaderTitle("PE signature"));
  out.push(`<dl>`);
  out.push(dd("Signature", "PE", "The PE\\0\\0 signature precedes the COFF file header and identifies the image as PE/COFF."));
  out.push(`</dl>`);
  out.push(renderInlineHeaderTitle("COFF file header"));
  out.push(`<dl>`);
  out.push(dd("Machine", rowOpts(pe.coff.Machine, MACHINE), "Target CPU architecture. The highlighted chip indicates the Machine field value."));
  out.push(dd("NumberOfSections", `${pe.coff.NumberOfSections}`, "Number of section headers that immediately follow the optional header."));
  out.push(dd("TimeDateStamp", isoOrDash(pe.coff.TimeDateStamp), "Link time as Unix epoch. Toolchains sometimes set this to reproducible values."));
  out.push(dd("PointerToSymbolTable", hex(pe.coff.PointerToSymbolTable, 8), "COFF symbol table pointer (deprecated, usually 0)."));
  out.push(dd("NumberOfSymbols", String(pe.coff.NumberOfSymbols), "COFF symbol count (deprecated)."));
  out.push(dd("SizeOfOptionalHeader", `${pe.coff.SizeOfOptionalHeader} bytes`, "Size of the optional header (standard + Windows-specific)."));
  out.push(dd("Characteristics", rowFlags(pe.coff.Characteristics, CHAR_FLAGS), "Flags describing image traits (DLL, system file, etc.)."));
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
    dd(
      "Magic",
      rowOpts(oh.Magic, [[PE32_OPTIONAL_HEADER_MAGIC, "PE32"], [PE32_PLUS_OPTIONAL_HEADER_MAGIC, "PE32+"], [ROM_OPTIONAL_HEADER_MAGIC, "ROM"]]),
      "Identifies PE32 (32-bit), PE32+ (64-bit), or IMAGE_ROM_OPTIONAL_HEADER."
    )
  );
  out.push(
    dd(
      "LinkerVersion",
      linkerVersionHint(oh.LinkerMajor, oh.LinkerMinor),
      "Linker that produced this image (MSVC or lld-link version family)."
    )
  );
  out.push(dd("SizeOfCode", humanSize(oh.SizeOfCode), "Size of code section bytes."));
  out.push(
    dd(
      "SizeOfInitializedData",
      humanSize(oh.SizeOfInitializedData),
      "Size of initialized data section bytes."
    )
  );
  out.push(
    dd(
      "SizeOfUninitializedData",
      humanSize(oh.SizeOfUninitializedData),
      "Size of uninitialized data bytes (BSS)."
    )
  );
  out.push(
    dd(
      "AddressOfEntryPoint",
      hex(oh.AddressOfEntryPoint, 8),
      oh.Magic === ROM_OPTIONAL_HEADER_MAGIC
        ? "Entry-point address stored in IMAGE_ROM_OPTIONAL_HEADER."
        : "RVA of entry point. Zero for DLLs without a preferred entry."
    )
  );
  out.push(dd("EntrySection", pe.entrySection ? safe(pe.entrySection.name || "(unnamed)") : "-", entrySectionInfo));
  if (oh.Magic === ROM_OPTIONAL_HEADER_MAGIC) {
    out.push(dd("BaseOfCode", hex(oh.BaseOfCode, 8), "Base address of code within the ROM image."));
    out.push(dd("BaseOfData", hex(oh.BaseOfData, 8), "Base address of initialized data within the ROM image."));
    out.push(dd("BaseOfBss", hex(oh.rom.BaseOfBss, 8), "Base address of uninitialized data within the ROM image."));
    out.push(dd("GprMask", hex(oh.rom.GprMask, 8), "General-purpose register mask recorded by the ROM toolchain."));
    out.push(dd("CprMask", safe(formatWordListHex(oh.rom.CprMask)), "Coprocessor register masks recorded by the ROM toolchain."));
    out.push(dd("GpValue", hex(oh.rom.GpValue, 8), "Global-pointer seed value recorded in IMAGE_ROM_OPTIONAL_HEADER."));
    out.push(`</dl>`);
    out.push(`<div class="smallNote">ROM optional headers stop here: Windows-only fields such as ImageBase, SectionAlignment, Subsystem, CheckSum, stack/heap sizes, and the PE data-directory array are not part of IMAGE_ROM_OPTIONAL_HEADER.</div>`);
    out.push(renderPeSectionEnd());
  } else {
    const pointerWidth = oh.Magic === PE32_PLUS_OPTIONAL_HEADER_MAGIC ? 16 : 8;
    out.push(dd("ImageBase", formatPointerHex(oh.ImageBase, pointerWidth), "Preferred load address."));
    out.push(dd("SectionAlignment", humanSize(oh.SectionAlignment), "Alignment of sections in memory."));
    out.push(dd("FileAlignment", humanSize(oh.FileAlignment), "Alignment of sections in the file."));
    out.push(dd("OperatingSystemVersion", winVersionName(oh.OSVersionMajor, oh.OSVersionMinor), "Minimum required OS version."));
    out.push(dd("ImageVersion", `${oh.ImageVersionMajor}.${oh.ImageVersionMinor}`, "Image version (informational)."));
    out.push(dd("SubsystemVersion", `${oh.SubsystemVersionMajor}.${oh.SubsystemVersionMinor}`, "Minimum subsystem version."));
    out.push(dd("Subsystem", rowOpts(oh.Subsystem, SUBSYSTEMS), "Required subsystem (GUI, CUI, etc.)."));
    out.push(dd("DllCharacteristics", rowFlags(oh.DllCharacteristics, DLL_FLAGS), "DLL characteristics (ASLR, DEP, etc.)."));
    out.push(dd("SizeOfImage", humanSize(oh.SizeOfImage), "Size of image in memory, including all headers and sections."));
    out.push(dd("SizeOfHeaders", humanSize(oh.SizeOfHeaders), "Combined size of DOS stub, PE header, and section headers."));
    const checksumHtml = [
      `<div style="display:flex;flex-direction:column;gap:.35rem">`,
      `<div class="mono">${safe(hex(oh.CheckSum, 8))}</div>`,
      `<div class="smallNote">Validation: <span id="peChecksumStatus">Not validated yet.</span></div>`,
      `<div class="smallNote">Computed: <span class="mono" id="peChecksumComputed">-</span></div>`,
      `<div><button type="button" class="actionButton" id="peChecksumValidateButton">Validate CheckSum</button></div>`,
      `</div>`
    ].join("");
    out.push(dd("CheckSum", checksumHtml, "Image checksum (used by some system components)."));
    out.push(dd("SizeOfStackReserve", formatBigByteSize(oh.SizeOfStackReserve), "Stack reservation size."));
    out.push(dd("SizeOfStackCommit", formatBigByteSize(oh.SizeOfStackCommit), "Stack commit size."));
    out.push(dd("SizeOfHeapReserve", formatBigByteSize(oh.SizeOfHeapReserve), "Heap reservation size."));
    out.push(dd("SizeOfHeapCommit", formatBigByteSize(oh.SizeOfHeapCommit), "Heap commit size."));
    out.push(`</dl>`);
    out.push(renderPeSectionEnd());
  }
  renderDataDirectories(pe, out);
  renderSections(pe, out);
  const coffTailSummary = renderCoffTailSummary(pe);
  if (coffTailSummary) out.push(coffTailSummary);
}
