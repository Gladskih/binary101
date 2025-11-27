"use strict";

import { humanSize, hex, isoOrDash } from "../../binary-utils.js";
import { dd, rowOpts, rowFlags, safe } from "../../html-utils.js";
import { MACHINE, SUBSYSTEMS, CHAR_FLAGS, DLL_FLAGS, SEC_FLAG_TEXTS, DD_TIPS } from "../../analyzers/pe/constants.js";
import type { PeParseResult } from "../../analyzers/pe/index.js";

const SECTION_HINTS: Record<string, string> = {
  ".text": "Code (executable instructions)",
  ".rdata": "Read-only data (constants, import name table)",
  ".data": "Initialized writable data",
  ".bss": "Uninitialized data (zero-initialized at load)",
  ".rsrc": "Resource tree (icons, dialogs, manifests)",
  ".reloc": "Base relocations",
  ".tls": "Thread Local Storage",
  ".pdata": "Exception pdata (x64 unwind info)"
};

const knownSectionName = (name: string): string | null => SECTION_HINTS[name.toLowerCase()] || null;

const linkerVersionHint = (major: number, minor: number): string => {
  const version = `${major}.${minor}`;
  const map: Record<string, string> = {
    "6.0": "VS6 (VC++ 6.0)",
    "7.0": "VS2002",
    "7.1": "VS2003",
    "8.0": "VS2005",
    "9.0": "VS2008",
    "10.0": "VS2010",
    "11.0": "VS2012",
    "12.0": "VS2013",
    "14.0": "VS2015 era",
    "14.1": "VS2017 era",
    "14.2": "VS2019 era",
    "14.3": "VS2022 era"
  };
  const hint =
    map[`${major}.0`] ||
    map[version] ||
    (major >= 14 ? "MSVC (VS2015+ era or lld-link)" : "MSVC (pre-VS2015)");
  return `${version} - ${hint}`;
};

const winVersionName = (major: number, minor: number): string => {
  const key = `${major}.${minor}`;
  const names: Record<string, string> = {
    "5.1": "Windows XP",
    "5.2": "Windows Server 2003",
    "6.0": "Windows Vista",
    "6.1": "Windows 7",
    "6.2": "Windows 8",
    "6.3": "Windows 8.1",
    "10.0": "Windows 10+"
  };
  const label = names[key] || key;
  return `${label} (${key})`;
};

const renderDataDirectories = (pe: PeParseResult, out: string[]): void => {
  if (!pe.dirs?.length) return;
  out.push(`<section><h4 style="margin:0 0 .5rem 0;font-size:.9rem">Data directories</h4><dl>`);
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
  out.push(`</dl></section>`);
};

const renderSections = (pe: PeParseResult, out: string[]): void => {
  const sections = pe.sections || [];
  if (!sections.length) return;
  out.push(`<section><h4 style="margin:0 0 .5rem 0;font-size:.9rem">Section headers</h4>`);
  out.push(
    `<table class="table"><thead><tr><th>Name</th><th>VirtualSize</th><th>RVA</th><th>RawSize</th><th>FilePtr</th><th>Entropy</th><th>Flags</th></tr></thead><tbody>`
  );
  sections.forEach(section => {
    const flags = SEC_FLAG_TEXTS.filter(([bit]) => (section.characteristics & bit) !== 0).map(([, text]) => text);
    const hint = knownSectionName(section.name);
    const nameCell = hint
      ? `<span title="${safe(hint)}"><b>${safe(section.name)}</b></span>`
      : `<span title="User-defined">${safe(section.name)}</span>`;
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
  out.push(`</tbody></table></section>`);
};

export function renderHeaders(pe: PeParseResult, out: string[]): void {
  const bits = pe.opt.isPlus ? "64-bit" : "32-bit";
  const isDll = (pe.coff.Characteristics & 0x2000) !== 0;
  const roleText = isDll ? "dynamic-link library (DLL)" : "executable image";
  const sectionCount = Array.isArray(pe.sections) ? pe.sections.length : pe.coff.NumberOfSections;
  out.push(`<section><h4 style="margin:0 0 .5rem 0;font-size:.9rem">Big picture</h4>`);
  out.push(
    `<div class="smallNote">PE image: ${bits} Windows ${roleText}. Headers describe layout and loader requirements; ${sectionCount} sections carry code, data, resources and relocation information.</div>`
  );
  const entryVa = pe.opt.ImageBase + (pe.opt.AddressOfEntryPoint >>> 0);
  out.push(
    `<div class="smallNote">Entry point RVA ${hex(
      pe.opt.AddressOfEntryPoint,
      8
    )} (VA 0x${entryVa.toString(16)}). Imports, relocations, resources and security directories below show how this image integrates with the operating system.</div>`
  );
  out.push(`</section>`);

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
  out.push(`</div></details></section>`);

  out.push(`<section><h4 style="margin:0 0 .5rem 0;font-size:.9rem">PE signature</h4><dl>${dd("Signature", "PE", "The PE\\0\\0 signature follows the DOS header.")}</dl></section>`);

  out.push(`<section><h4 style="margin:0 0 .5rem 0;font-size:.9rem">COFF header</h4><dl>`);
  out.push(dd("Machine", rowOpts(pe.coff.Machine, MACHINE), "Target CPU architecture. The highlighted chip indicates the Machine field value."));
  out.push(dd("NumberOfSections", `${pe.coff.NumberOfSections}`, "Number of section headers that immediately follow the optional header."));
  out.push(dd("TimeDateStamp", isoOrDash(pe.coff.TimeDateStamp), "Link time as Unix epoch. Toolchains sometimes set this to reproducible values."));
  out.push(dd("PointerToSymbolTable", hex(pe.coff.PointerToSymbolTable, 8), "COFF symbol table pointer (deprecated, usually 0)."));
  out.push(dd("NumberOfSymbols", String(pe.coff.NumberOfSymbols), "COFF symbol count (deprecated)."));
  out.push(dd("SizeOfOptionalHeader", `${pe.coff.SizeOfOptionalHeader} bytes`, "Size of the optional header (standard + Windows-specific)."));
  out.push(dd("Characteristics", rowFlags(pe.coff.Characteristics, CHAR_FLAGS), "Flags describing image traits (DLL, system file, etc.)."));
  out.push(`</dl></section>`);

  const oh = pe.opt;
  const isPlus = oh.isPlus;
  out.push(`<section><h4 style="margin:0 0 .5rem 0;font-size:.9rem">Optional header</h4><dl>`);
  out.push(dd("Magic", rowOpts(oh.Magic, [[0x010b, "PE32"], [0x020b, "PE32+"], [0x0107, "ROM"]]), "Identifies PE32 (32-bit) or PE32+ (64-bit)."));
  out.push(dd("LinkerVersion", linkerVersionHint(oh.LinkerMajor, oh.LinkerMinor), "Linker that produced this image (MSVC or lld-link version family)."));
  out.push(dd("SizeOfCode", humanSize(oh.SizeOfCode), "Size of code (text) section(s)."));
  out.push(dd("SizeOfInitializedData", humanSize(oh.SizeOfInitializedData), "Size of initialized data section(s)."));
  out.push(dd("SizeOfUninitializedData", humanSize(oh.SizeOfUninitializedData), "Size of uninitialized data section(s) (BSS)."));
  out.push(dd("AddressOfEntryPoint", hex(oh.AddressOfEntryPoint, 8), "RVA of entry point. Zero for DLLs without a preferred entry."));
  const entrySectionInfo = pe.entrySection
    ? `Usually points into section ${pe.entrySection.name || "(unnamed)"} (index ${pe.entrySection.index}).`
    : "Should point into one of the code sections.";
  out.push(dd("EntrySection", pe.entrySection ? safe(pe.entrySection.name || "(unnamed)") : "-", entrySectionInfo));
  out.push(dd("ImageBase", hex(oh.ImageBase, isPlus ? 16 : 8), "Preferred load address."));
  out.push(dd("SectionAlignment", humanSize(oh.SectionAlignment), "Alignment of sections in memory."));
  out.push(dd("FileAlignment", humanSize(oh.FileAlignment), "Alignment of sections in the file."));
  out.push(dd("OperatingSystemVersion", winVersionName(oh.OSVersionMajor, oh.OSVersionMinor), "Minimum required OS version."));
  out.push(dd("ImageVersion", `${oh.ImageVersionMajor}.${oh.ImageVersionMinor}`, "Image version (informational)."));
  out.push(dd("SubsystemVersion", `${oh.SubsystemVersionMajor}.${oh.SubsystemVersionMinor}`, "Minimum subsystem version."));
  out.push(dd("Subsystem", rowOpts(oh.Subsystem, SUBSYSTEMS), "Required subsystem (GUI, CUI, etc.)."));
  out.push(dd("DllCharacteristics", rowFlags(oh.DllCharacteristics, DLL_FLAGS), "DLL characteristics (ASLR, DEP, etc.)."));
  out.push(dd("SizeOfImage", humanSize(oh.SizeOfImage), "Size of image in memory, including all headers and sections."));
  out.push(dd("SizeOfHeaders", humanSize(oh.SizeOfHeaders), "Combined size of DOS stub, PE header, and section headers."));
  out.push(dd("CheckSum", hex(oh.CheckSum, 8), "Image checksum (used by some system components)."));
  out.push(dd("SizeOfStackReserve", humanSize(oh.SizeOfStackReserve), "Stack reservation size."));
  out.push(dd("SizeOfStackCommit", humanSize(oh.SizeOfStackCommit), "Stack commit size."));
  out.push(dd("SizeOfHeapReserve", humanSize(oh.SizeOfHeapReserve), "Heap reservation size."));
  out.push(dd("SizeOfHeapCommit", humanSize(oh.SizeOfHeapCommit), "Heap commit size."));
  out.push(`</dl></section>`);

  renderDataDirectories(pe, out);
  renderSections(pe, out);
}
