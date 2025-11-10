"use strict";

import { dd, rowOpts, rowFlags, humanSize, hex, isoOrDash, safe } from "./utils.js";
import { MACHINE, SUBSYSTEMS, CHAR_FLAGS, DLL_FLAGS, SEC_FLAG_TEXTS, GUARD_FLAGS, DD_TIPS } from "./analyzers/pe.js";

const sectionHintMap = {
  ".text": "Code (executable instructions)",
  ".rdata": "Read-only data (constants, import name table)",
  ".data": "Initialized writable data",
  ".bss": "Uninitialized data (zero-initialized at load)",
  ".rsrc": "Resource tree (icons, dialogs, manifests)",
  ".reloc": "Base relocations",
  ".tls": "Thread Local Storage",
  ".pdata": "Exception pdata (x64 unwind info)"
};

const knownSectionName = n => sectionHintMap[n.toLowerCase()] || null;

function linkerVersionHint(maj, min) {
  const v = `${maj}.${min}`;
  const map = {
    "6.0": "VS6 (VC++ 6.0)", "7.0": "VS2002", "7.1": "VS2003", "8.0": "VS2005", "9.0": "VS2008",
    "10.0": "VS2010", "11.0": "VS2012", "12.0": "VS2013", "14.0": "VS2015 era", "14.1": "VS2017 era",
    "14.2": "VS2019 era", "14.3": "VS2022 era"
  };
  const hint = map[`${maj}.0`] || map[v] || (maj >= 14 ? "MSVC (VS2015+ era or lld-link)" : "MSVC (pre-VS2015)");
  return `${v} — ${hint}`;
}

function winVersionName(maj, min) {
  const k = `${maj}.${min}`;
  const names = { "5.1": "Windows XP", "5.2": "Windows Server 2003", "6.0": "Windows Vista", "6.1": "Windows 7", "6.2": "Windows 8", "6.3": "Windows 8.1", "10.0": "Windows 10+" };
  return (names[k] || k) + ` (${k})`;
}

export function renderPe(pe) {
  if (!pe) return "";
  const out = [];

  // DOS header
  out.push(`<section><h4 style="margin:0 0 .5rem 0;font-size:.9rem">DOS header</h4><dl>`);
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
  out.push(dd("e_lfarlc", hex(pe.dos.e_lfarlc, 4), "Offset to relocation table within DOS header (usually 0x40)."));
  out.push(dd("e_oemid", hex(pe.dos.e_oemid, 4), "OEM identifier."));
  out.push(dd("e_oeminfo", hex(pe.dos.e_oeminfo, 4), "OEM-specific information."));
  out.push(dd("e_lfanew", hex(pe.dos.e_lfanew, 8), "File offset to PE signature (" + (pe.dos.e_lfanew >= 0x80 ? "typically near end of headers" : "") + ")."));
  out.push(`</dl>`);
  const s = pe.dos.stub;
  out.push(`<div class="smallNote">DOS stub: ${s.kind}${s.note ? ` — ${safe(s.note)}` : ""}</div>`);
  if (s.strings?.length) out.push(`<div class="mono smallNote">${s.strings.map(x => `<div>${safe(String(x))}</div>`).join("")}</div>`);
  out.push(`</section>`);

  // PE signature
  out.push(`<section><h4 style="margin:0 0 .5rem 0;font-size:.9rem">PE signature</h4><dl>${dd("Signature", "PE", "The PE\x00\x00 signature follows the DOS header.")}</dl></section>`);

  // COFF header
  out.push(`<section><h4 style="margin:0 0 .5rem 0;font-size:.9rem">COFF header</h4><dl>`);
  out.push(dd("Machine", rowOpts(pe.coff.Machine, MACHINE), "Target CPU architecture. The highlighted chip indicates the Machine field value."));
  out.push(dd("NumberOfSections", `${pe.coff.NumberOfSections}`, "Number of section headers that immediately follow the optional header."));
  out.push(dd("TimeDateStamp", isoOrDash(pe.coff.TimeDateStamp), "Link time as Unix epoch. Toolchains sometimes set this to reproducible values."));
  out.push(dd("PointerToSymbolTable", hex(pe.coff.PointerToSymbolTable, 8), "COFF symbol table pointer (deprecated, usually 0)."));
  out.push(dd("NumberOfSymbols", String(pe.coff.NumberOfSymbols), "COFF symbol count (deprecated)."));
  out.push(dd("SizeOfOptionalHeader", `${pe.coff.SizeOfOptionalHeader} bytes`, "Size of the optional header (standard + Windows-specific)."));
  out.push(dd("Characteristics", rowFlags(pe.coff.Characteristics, CHAR_FLAGS), "Flags describing image traits (DLL, system file, etc.)."));
  out.push(`</dl></section>`);

  // Optional header (Windows-specific)
  const oh = pe.opt, isPlus = oh.isPlus;
  out.push(`<section><h4 style="margin:0 0 .5rem 0;font-size:.9rem">Optional header</h4><dl>`);
  out.push(dd("Magic", rowOpts(oh.Magic, [[0x010b, "PE32"], [0x020b, "PE32+"], [0x0107, "ROM"]]), "Identifies PE32 (32-bit) or PE32+ (64-bit)."));
  out.push(dd("LinkerVersion", linkerVersionHint(oh.LinkerMajor, oh.LinkerMinor), "Linker that produced this image (MSVC or lld-link version family).") );
  out.push(dd("SizeOfCode", humanSize(oh.SizeOfCode), "Total size of all code sections (typically .text)."));
  out.push(dd("SizeOfInitializedData", humanSize(oh.SizeOfInitializedData), "Total size of all initialized data (.rdata, .data)."));
  out.push(dd("SizeOfUninitializedData", humanSize(oh.SizeOfUninitializedData), "Total size of uninitialized data (.bss)."));
  out.push(dd("AddressOfEntryPoint", hex(oh.AddressOfEntryPoint, 8), "RVA of process/thread entry point."));
  out.push(dd("BaseOfCode", hex(oh.BaseOfCode, 8), "RVA where code section (.text) begins."));
  if (oh.BaseOfData !== undefined) out.push(dd("BaseOfData", hex(oh.BaseOfData, 8), "RVA where data section (.data) begins (PE32 only)."));
  out.push(dd("ImageBase", isPlus ? ("0x" + BigInt(oh.ImageBase).toString(16)) : hex(oh.ImageBase, 8), "Preferred image load address (virtual address)."));
  out.push(dd("SectionAlignment", hex(oh.SectionAlignment, 8), "Alignment of sections when loaded into memory."));
  out.push(dd("FileAlignment", hex(oh.FileAlignment, 8), "Alignment of section data within the file."));
  out.push(dd("OSVersion", winVersionName(oh.OSVersionMajor, oh.OSVersionMinor), "Minimum required OS version for the image."));
  out.push(dd("ImageVersion", `${oh.ImageVersionMajor}.${oh.ImageVersionMinor}`, "Image version (informational)."));
  out.push(dd("SubsystemVersion", `${oh.SubsystemVersionMajor}.${oh.SubsystemVersionMinor}`, "Minimum subsystem version (e.g., Windows GUI/CUI)."));
  out.push(dd("Win32VersionValue", hex(oh.Win32VersionValue, 8), "Reserved (should be 0)."));
  out.push(dd("SizeOfImage", humanSize(oh.SizeOfImage), "Aligned size of the image in memory (sum of section virtual sizes)."));
  out.push(dd("SizeOfHeaders", humanSize(oh.SizeOfHeaders), "Combined size of all headers rounded up to file alignment."));
  out.push(dd("CheckSum", hex(oh.CheckSum, 8), "PE checksum used by some loaders; not security relevant for modern Windows."));
  out.push(dd("Subsystem", rowOpts(oh.Subsystem, SUBSYSTEMS), "Execution subsystem required (GUI, CUI, native, EFI etc.)."));
  out.push(dd("DllCharacteristics", rowFlags(oh.DllCharacteristics, DLL_FLAGS), "Security and loader flags (ASLR, DEP, CFG, AppContainer)."));
  out.push(dd("SizeOfStackReserve", humanSize(oh.SizeOfStackReserve), "Initial stack reservation size."));
  out.push(dd("SizeOfStackCommit", humanSize(oh.SizeOfStackCommit), "Initial stack commit size."));
  out.push(dd("SizeOfHeapReserve", humanSize(oh.SizeOfHeapReserve), "Initial process heap reservation size."));
  out.push(dd("SizeOfHeapCommit", humanSize(oh.SizeOfHeapCommit), "Initial process heap commit size."));
  out.push(dd("LoaderFlags", hex(oh.LoaderFlags, 8), "Reserved (should be 0)."));
  out.push(dd("NumberOfRvaAndSizes", `${oh.NumberOfRvaAndSizes} (0..16)`, "Number of data directories present in the optional header."));
  out.push(`</dl></section>`);

  // Data directories
  if (pe.dirs.length) {
    out.push(`<section><h4 style="margin:0 0 .5rem 0;font-size:.9rem">Data directories</h4><dl>`);
    for (const d of pe.dirs) out.push(dd("[" + d.index + "] " + d.name, `RVA ${hex(d.rva, 8)}, Size ${humanSize(d.size)}`, DD_TIPS[d.name] || "Directory"));
    out.push(`</dl></section>`);
  }

  // Sections table with entropy
  if (pe.sections.length) {
    out.push(`<section><h4 style="margin:0 0 .5rem 0;font-size:.9rem">Section headers</h4>`);
    out.push(`<table class="table"><thead><tr><th>Name</th><th>VirtualSize</th><th>RVA</th><th>RawSize</th><th>FilePtr</th><th>Entropy</th><th>Flags</th></tr></thead><tbody>`);
    for (const s of pe.sections) {
      const flags = SEC_FLAG_TEXTS.filter(([bit]) => (s.characteristics & bit) !== 0).map(([, txt]) => txt);
      const hint = knownSectionName(s.name);
      const nameCell = hint ? `<span title="${safe(hint)}"><b>${safe(s.name)}</b></span>` : `<span title="User-defined">${safe(s.name)}</span>`;
      out.push(`<tr>
        <td>${nameCell}</td>
        <td>${humanSize(s.virtualSize)}</td>
        <td>${hex(s.virtualAddress, 8)}</td>
        <td>${humanSize(s.sizeOfRawData)}</td>
        <td>${hex(s.pointerToRawData, 8)}</td>
        <td title="Shannon entropy (0..8 bits/byte)">${(s.entropy ?? 0).toFixed(2)}</td>
        <td>${flags.join(" &middot; ")}</td>
      </tr>`);
    }
    out.push(`</tbody></table></section>`);
  }

  // Load Config
  if (pe.loadcfg) {
    const lc = pe.loadcfg;
    out.push(`<section><h4 style="margin:0 0 .5rem 0;font-size:.9rem">Load Config</h4><dl>`);
    out.push(dd("Size", hex(lc.Size, 8), "Structure size of IMAGE_LOAD_CONFIG_DIRECTORY."));
    out.push(dd("TimeDateStamp", isoOrDash(lc.TimeDateStamp), "Build timestamp for load config data."));
    out.push(dd("Version", `${lc.Major}.${lc.Minor}`, "Load config version (varies between OS/toolchain versions)."));
    out.push(dd("SecurityCookie", lc.SecurityCookie ? (pe.opt.isPlus ? "0x" + BigInt(lc.SecurityCookie).toString(16) : hex(lc.SecurityCookie, 8)) : "-", "Address of the GS cookie (stack guard)."));
    out.push(dd("SEHandlerTable", lc.SEHandlerTable ? (pe.opt.isPlus ? "0x" + BigInt(lc.SEHandlerTable).toString(16) : hex(lc.SEHandlerTable, 8)) : "-", "SafeSEH handler table (x86 only)."));
    out.push(dd("SEHandlerCount", lc.SEHandlerCount ?? "-", "Number of SafeSEH handlers (x86)."));
    out.push(dd("GuardCFFunctionTable", lc.GuardCFFunctionTable ? (pe.opt.isPlus ? "0x" + BigInt(lc.GuardCFFunctionTable).toString(16) : hex(lc.GuardCFFunctionTable, 8)) : "-", "CFG function table VA."));
    out.push(dd("GuardCFFunctionCount", lc.GuardCFFunctionCount ?? "-", "Number of CFG functions listed."));
    out.push(dd("GuardFlags", lc.GuardFlags ? rowFlags(lc.GuardFlags, GUARD_FLAGS) : "-", "Control Flow Guard flags."));
    out.push(`</dl></section>`);
  }

  // Debug (PDB)
  if (pe.rsds) {
    out.push(`<section><h4 style="margin:0 0 .5rem 0;font-size:.9rem">Debug (PDB)</h4><dl>`);
    out.push(dd("CodeView", "RSDS", "CodeView format signature (RSDS)."));
    out.push(dd("GUID", pe.rsds.guid, "PDB signature GUID used to match correct PDB file."));
    out.push(dd("Age", String(pe.rsds.age), "PDB age; increments on certain rebuilds."));
    out.push(dd("Path", pe.rsds.path, "Path to PDB as recorded at link time (can be absolute)."));
    out.push(`</dl></section>`);
  }

  // Import table
  if (pe.imports?.length) {
    out.push(`<section><h4 style="margin:0 0 .5rem 0;font-size:.9rem">Import table</h4><div class="smallNote">Hint index speeds up runtime name lookup. Ordinal imports may indicate special APIs.</div>`);
    for (const mod of pe.imports) {
      out.push(`<div class="smallNote" style="margin-top:.35rem"><b>${safe(mod.dll || "(unknown DLL)")}</b> — ${mod.functions.length} function(s)</div>`);
      if (mod.functions.length) {
        out.push(`<table class="table"><thead><tr><th>#</th><th>Hint</th><th>Name / Ordinal</th></tr></thead><tbody>`);
        mod.functions.forEach((f, i) => {
          const hint = f.hint != null ? String(f.hint) : "-";
          const nm = f.name ? safe(f.name) : (f.ordinal != null ? ("ORD " + f.ordinal) : "-");
          out.push(`<tr><td>${i + 1}</td><td>${hint}</td><td>${nm}</td></tr>`);
        });
        out.push(`</tbody></table>`);
      }
    }
    out.push(`</section>`);
  }

  // Export directory
  if (pe.exports) {
    const ex = pe.exports;
    out.push(`<section><h4 style="margin:0 0 .5rem 0;font-size:.9rem">Export directory</h4><dl>`);
    out.push(dd("Name", safe(ex.dllName || ""), "Exported DLL name recorded by the linker."));
    out.push(dd("OrdinalBase", String(ex.Base), "Base value added to function indices to form ordinals."));
    out.push(dd("Functions", String(ex.NumberOfFunctions), "Total entries in Export Address Table (including unnamed)."));
    out.push(dd("Names", String(ex.NumberOfNames), "Number of entries with names (Export Name Ptr & Ord tables)."));
    out.push(`</dl>`);
    if (ex.entries?.length) {
      out.push(`<table class="table"><thead><tr><th>#</th><th>Ordinal</th><th>Name</th><th>RVA</th><th>Forwarder</th></tr></thead><tbody>`);
      ex.entries.slice(0, 2000).forEach((e, i) => {
        out.push(`<tr><td>${i + 1}</td><td>${e.ordinal}</td><td>${e.name ? safe(e.name) : "-"}</td><td>${hex(e.rva, 8)}</td><td>${e.forwarder ? safe(e.forwarder) : "-"}</td></tr>`);
      });
      out.push(`</tbody></table>`);
    }
    out.push(`</section>`);
  }

  // TLS directory
  if (pe.tls) {
    const t = pe.tls;
    out.push(`<section><h4 style="margin:0 0 .5rem 0;font-size:.9rem">TLS directory</h4><dl>`);
    out.push(dd("StartAddressOfRawData", "0x" + BigInt(t.StartAddressOfRawData).toString(16), "VA for beginning of TLS template data."));
    out.push(dd("EndAddressOfRawData", "0x" + BigInt(t.EndAddressOfRawData).toString(16), "VA for end of TLS template data."));
    out.push(dd("AddressOfIndex", "0x" + BigInt(t.AddressOfIndex).toString(16), "VA of TLS index used by the loader."));
    out.push(dd("AddressOfCallBacks", "0x" + BigInt(t.AddressOfCallBacks).toString(16), "VA of null-terminated array of TLS callbacks (if present)."));
    out.push(dd("CallbackCount", String(t.CallbackCount ?? 0), "Number of TLS callbacks determined by scanning the callback pointer array until a NULL entry."));
    out.push(dd("SizeOfZeroFill", String(t.SizeOfZeroFill), "Bytes of zero-fill padding (TLS)."));
    out.push(dd("Characteristics", hex(t.Characteristics || 0, 8), "Reserved (should be 0)."));
    out.push(`</dl></section>`);
  }

  // Base relocations summary
  if (pe.reloc) {
    const r = pe.reloc;
    out.push(`<section><h4 style="margin:0 0 .5rem 0;font-size:.9rem">Base relocations</h4><dl>`);
    out.push(dd("Blocks", String(r.blocks.length), "Number of relocation blocks in .reloc."));
    out.push(dd("TotalEntries", String(r.totalEntries), "Sum of relocation entries across all blocks."));
    out.push(`</dl></section>`);
  }

  // Sanity & overlay
  out.push(`<section><h4 style="margin:0 0 .5rem 0;font-size:.9rem">Sanity</h4><dl>`);
  out.push(dd("ComputedImageEnd", hex(pe.imageEnd || 0, 8), "Computed image end (max section RVA + aligned size)."));
  out.push(dd("SizeOfImage", hex(pe.opt.SizeOfImage || 0, 8), "Declared SizeOfImage in optional header."));
  out.push(dd("ImageSizeMismatch", pe.imageSizeMismatch ? "Yes" : "No", "Whether computed in-memory image size differs from SizeOfImage."));
  out.push(dd("OverlaySize", humanSize(pe.overlaySize || 0), "Bytes at the end of file past the last section's raw data."));
  out.push(`</dl></section>`);

  return out.join("");
}

