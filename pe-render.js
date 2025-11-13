"use strict";

import { dd, rowOpts, rowFlags, humanSize, hex, isoOrDash, safe } from "./utils.js";
import { MACHINE, SUBSYSTEMS, CHAR_FLAGS, DLL_FLAGS, SEC_FLAG_TEXTS, GUARD_FLAGS, DD_TIPS } from "./analyzers/pe-constants.js";

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
  const bits = pe.opt.isPlus ? "64-bit" : "32-bit";
  const isDll = (pe.coff.Characteristics & 0x2000) !== 0;
  const roleText = isDll ? "a reusable library (DLL)" : "an executable program";
  const sectionCount = Array.isArray(pe.sections) ? pe.sections.length : pe.coff.NumberOfSections;
  out.push(`<section><h4 style="margin:0 0 .5rem 0;font-size:.9rem">Big picture</h4>`);
  out.push(`<div class="smallNote">This Portable Executable is a ${bits} Windows ${roleText}. The file is split into headers (rules and map) and ${sectionCount} sections (code, data, resources and more).</div>`);
  out.push(`<div class="smallNote">You can read it like a book: DOS and PE headers are the table of contents, the section table lists the chapters, and later views show imports, exports, resources and security so you can see how the program talks to the operating system.</div>`);
  out.push(`</section>`);

  // DOS header
  out.push(`<section>`);
  out.push(`<details><summary style="cursor:pointer;padding:.35rem .6rem;border:1px solid var(--border2);border-radius:8px;background:var(--chip-bg)"><b>DOS header</b> (click to expand)</summary>`);
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
  out.push(dd("e_lfarlc", hex(pe.dos.e_lfarlc, 4), "Offset to relocation table within DOS header (usually 0x40)."));
  out.push(dd("e_oemid", hex(pe.dos.e_oemid, 4), "OEM identifier."));
  out.push(dd("e_oeminfo", hex(pe.dos.e_oeminfo, 4), "OEM-specific information."));
  out.push(dd("e_lfanew", hex(pe.dos.e_lfanew, 8), "File offset to PE signature (" + (pe.dos.e_lfanew >= 0x80 ? "typically near end of headers" : "") + ")."));
  out.push(`</dl>`);
  const s = pe.dos.stub;
  out.push(`<div class="smallNote">DOS stub: ${s.kind}${s.note ? ` — ${safe(s.note)}` : ""}</div>`);
  if (s.strings?.length) out.push(`<div class="mono smallNote">${s.strings.map(x => `<div>${safe(String(x))}</div>`).join("")}</div>`);
  out.push(`</div></details></section>`);

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
  const entrySectionInfo = pe.entrySection ? `Usually points into section ${pe.entrySection.name || "(unnamed)"} (index ${pe.entrySection.index}).` : "Should point into one of the code sections.";
  out.push(dd("AddressOfEntryPoint", hex(oh.AddressOfEntryPoint, 8), `RVA of process/thread entry point. ${entrySectionInfo}`));
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
        <td title="Shannon entropy (0..8 bits/byte). Near 0 means very simple or empty, near 8 means very mixed data (often compressed or encrypted).">${(s.entropy ?? 0).toFixed(2)}</td>
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
    out.push(dd("GUID", (pe.rsds.guid||"").toUpperCase(), "PDB signature GUID used to match correct PDB file."));
    out.push(dd("Age", String(pe.rsds.age), "PDB age; increments on certain rebuilds."));
    out.push(dd("Path", pe.rsds.path, "Path to PDB as recorded at link time (can be absolute)."));
    out.push(`</dl></section>`);
  }

  // Import table
  if (pe.imports?.length) {
    out.push(`<section><h4 style="margin:0 0 .5rem 0;font-size:.9rem">Import table</h4><div class="smallNote">Imports list functions this file expects other modules to provide. Hint index speeds up runtime name lookup, and ordinal-only imports often point to more special or low-level routines.</div>`);
    for (const mod of pe.imports) {
      const dll = safe(mod.dll || "(unknown DLL)");
      out.push(`<details><summary style="cursor:pointer;padding:.25rem .5rem;border:1px solid var(--border2);border-radius:6px;background:var(--chip-bg)"><b>${dll}</b> — ${mod.functions.length} function(s)</summary>`);
      if (mod.functions.length) {
        out.push(`<table class="table" style="margin-top:.35rem"><thead><tr><th>#</th><th>Hint</th><th>Name / Ordinal</th></tr></thead><tbody>`);
        mod.functions.forEach((f, i) => {
          const hint = f.hint != null ? String(f.hint) : "-";
          const nm = f.name ? safe(f.name) : (f.ordinal != null ? ("ORD " + f.ordinal) : "-");
          out.push(`<tr><td>${i + 1}</td><td>${hint}</td><td>${nm}</td></tr>`);
        });
        out.push(`</tbody></table>`);
      }
      out.push(`</details>`);
    }
    out.push(`</section>`);
  }

  // Resources summary and details
  if (pe.resources?.top?.length) {
    const rs = pe.resources.top;
    out.push(`<section><h4 style="margin:0 0 .5rem 0;font-size:.9rem">Resources</h4>`);
    out.push(`<table class="table"><thead><tr><th>#</th><th>Type</th><th>Leaf items</th></tr></thead><tbody>`);
    rs.forEach((t, i) => out.push(`<tr><td>${i + 1}</td><td>${safe(t.typeName)}</td><td>${t.leafCount}</td></tr>`));
    out.push(`</tbody></table>`);
    if (pe.resources.detail?.length) {
      pe.resources.detail.forEach((tp, idx) => {
        out.push(`<details style="margin-top:.5rem"><summary style="cursor:pointer;padding:.25rem .5rem;border:1px solid var(--border2);border-radius:6px;background:var(--chip-bg)"><b>${safe(tp.typeName)}</b> — entries</summary>`);
        if (tp.entries?.length) {
          out.push(`<table class="table" style="margin-top:.35rem"><thead><tr><th>#</th><th>Name/ID</th><th>Lang</th><th>Size</th><th>CodePage</th><th>Preview</th></tr></thead><tbody>`);
          let row = 0;
          tp.entries.forEach(ent => {
            if (ent.langs?.length) {
              ent.langs.forEach(l => {
                const nm = ent.name ? safe(ent.name) : (ent.id != null ? ("ID " + ent.id) : "-");
                const lang = l.lang != null ? ("0x" + (l.lang>>>0).toString(16)) : "-";
                let prev = "-";
                if (l.previewKind === "image" && l.previewDataUrl) {
                  prev = `<img src="${l.previewDataUrl}" alt="icon" style="width:24px;height:24px;image-rendering:auto">`;
                } else if (l.previewKind === "text" && l.textPreview) {
                  const snip = (l.textPreview || "").slice(0,300);
                  prev = `<span class="mono" style="white-space:pre;display:inline-block;max-width:360px;overflow:hidden;text-overflow:ellipsis">${safe(snip)}</span>`;
                }
                out.push(`<tr><td>${++row}</td><td>${nm}</td><td>${lang}</td><td>${humanSize(l.size)}</td><td>${l.codePage}</td><td>${prev}</td></tr>`);
              });
            } else {
              const nm = ent.name ? safe(ent.name) : (ent.id != null ? ("ID " + ent.id) : "-");
              out.push(`<tr><td>${++row}</td><td>${nm}</td><td>-</td><td>-</td><td>-</td><td>-</td></tr>`);
            }
          });
          out.push(`</tbody></table>`);
        }
        out.push(`</details>`);
      });
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
      out.push(`<details><summary style="cursor:pointer;padding:.25rem .5rem;border:1px solid var(--border2);border-radius:6px;background:var(--chip-bg)">Show entries (${ex.entries.length})</summary>`);
      out.push(`<table class="table" style="margin-top:.35rem"><thead><tr><th>#</th><th>Ordinal</th><th>Name</th><th>RVA</th><th>Forwarder</th></tr></thead><tbody>`);
      ex.entries.slice(0, 2000).forEach((e, i) => {
        out.push(`<tr><td>${i + 1}</td><td>${e.ordinal}</td><td>${e.name ? safe(e.name) : "-"}</td><td>${hex(e.rva, 8)}</td><td>${e.forwarder ? safe(e.forwarder) : "-"}</td></tr>`);
      });
      out.push(`</tbody></table></details>`);
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

  // Exception directory (.pdata)
  if (pe.exception) {
    const e = pe.exception;
    out.push(`<section><h4 style="margin:0 0 .5rem 0;font-size:.9rem">Exception directory (.pdata)</h4>`);
    out.push(`<details><summary style="cursor:pointer;padding:.25rem .5rem;border:1px solid var(--border2);border-radius:6px;background:var(--chip-bg)">RUNTIME_FUNCTION count ${e.count}</summary>`);
    if (e.sample?.length) {
      out.push(`<table class="table" style="margin-top:.35rem"><thead><tr><th>#</th><th>BeginAddress (RVA)</th><th>EndAddress (RVA)</th><th>UnwindInfo (RVA)</th></tr></thead><tbody>`);
      e.sample.forEach((r, i) => out.push(`<tr><td>${i + 1}</td><td>${hex(r.BeginAddress, 8)}</td><td>${hex(r.EndAddress, 8)}</td><td>${hex(r.UnwindInfoAddress, 8)}</td></tr>`));
      out.push(`</tbody></table>`);
    }
    out.push(`</details></section>`);
  }

  // Bound imports
  if (pe.boundImports?.entries?.length) {
    const bi = pe.boundImports;
    out.push(`<section><h4 style="margin:0 0 .5rem 0;font-size:.9rem">Bound imports</h4>`);
    out.push(`<table class="table"><thead><tr><th>#</th><th>Module</th><th>ForwarderRefs</th><th>TimeDateStamp</th></tr></thead><tbody>`);
    bi.entries.forEach((x, i) => out.push(`<tr><td>${i + 1}</td><td>${safe(x.name)}</td><td>${x.NumberOfModuleForwarderRefs}</td><td>${isoOrDash(x.TimeDateStamp)}</td></tr>`));
    out.push(`</tbody></table></section>`);
  }

  // Delay-load imports
  if (pe.delayImports?.entries?.length) {
    const di = pe.delayImports;
    out.push(`<section><h4 style="margin:0 0 .5rem 0;font-size:.9rem">Delay-load imports</h4>`);
    di.entries.forEach((x, i) => {
      out.push(`<details><summary style="cursor:pointer;padding:.25rem .5rem;border:1px solid var(--border2);border-radius:6px;background:var(--chip-bg)"><b>${safe(x.name || '(unknown)')}</b> — ${x.functions?.length || 0} function(s)</summary>`);
      out.push(`<dl class="smallNote" style="margin-top:.35rem">`);
      out.push(dd("INT (RVA)", hex(x.ImportNameTableRVA, 8), "Import Name Table RVA for delay-load"));
      out.push(dd("IAT (RVA)", hex(x.ImportAddressTableRVA, 8), "Import Address Table RVA for delay-load"));
      out.push(dd("BoundIAT (RVA)", hex(x.BoundImportAddressTableRVA, 8), "Bound IAT RVA"));
      out.push(dd("UnloadIAT (RVA)", hex(x.UnloadInformationTableRVA, 8), "Unload IAT RVA"));
      out.push(dd("TimeDateStamp", isoOrDash(x.TimeDateStamp), "Timestamp for bound state or 0."));
      out.push(`</dl>`);
      if (x.functions?.length) {
        out.push(`<table class="table"><thead><tr><th>#</th><th>Hint</th><th>Name / Ordinal</th></tr></thead><tbody>`);
        x.functions.forEach((f, j) => {
          const hint = f.hint != null ? String(f.hint) : "-";
          const nm = f.name ? safe(f.name) : (f.ordinal != null ? ("ORD " + f.ordinal) : "-");
          out.push(`<tr><td>${j + 1}</td><td>${hint}</td><td>${nm}</td></tr>`);
        });
        out.push(`</tbody></table>`);
      }
      out.push(`</details>`);
    });
    out.push(`</section>`);
  }

  // CLR (.NET) header
  if (pe.clr) {
    const c = pe.clr;
    out.push(`<section><h4 style="margin:0 0 .5rem 0;font-size:.9rem">CLR (.NET) header</h4><dl>`);
    out.push(dd("Size", String(c.cb), "Size of IMAGE_COR20_HEADER in bytes."));
    out.push(dd("RuntimeVersion", `${c.MajorRuntimeVersion}.${c.MinorRuntimeVersion}`, "CLR runtime version required by this assembly."));
    out.push(dd("MetaData", `RVA ${hex(c.MetaDataRVA, 8)} Size ${humanSize(c.MetaDataSize)}`, "Location and size of CLR metadata streams (tables/heap)."));
    out.push(dd("Flags", rowFlags(c.Flags || 0, CLR_FLAG_TEXTS), "CLR flags (e.g., ILONLY, 32BITREQUIRED)."));
    out.push(dd("EntryPointToken", hex(c.EntryPointToken, 8), "Managed entry point token (method) if IL-only."));
    out.push(`</dl>`);
    if (c.meta) {
      out.push(`<div class="smallNote">Metadata version: ${safe(c.meta.version || '')}</div>`);
      if (c.meta.streams?.length) {
        out.push(`<details style="margin-top:.35rem"><summary>Metadata streams (${c.meta.streams.length})</summary>`);
        out.push(`<table class="table" style="margin-top:.35rem"><thead><tr><th>#</th><th>Name</th><th>Offset</th><th>Size</th></tr></thead><tbody>`);
        c.meta.streams.forEach((s, i) => out.push(`<tr><td>${i + 1}</td><td>${safe(s.name)}</td><td>${hex(s.offset, 8)}</td><td>${humanSize(s.size)}</td></tr>`));
        out.push(`</tbody></table></details>`);
      }
    }
    out.push(`</section>`);
  }

  // Security (WIN_CERTIFICATE)
  if (pe.security) {
    const s = pe.security;
    out.push(`<section><h4 style="margin:0 0 .5rem 0;font-size:.9rem">Security (WIN_CERTIFICATE)</h4><dl>`);
    out.push(dd("Certificate records", String(s.count ?? 0), "Number of certificate blobs present (Authenticode)."));
    out.push(`</dl>`);
    if (s.certs?.length) {
      out.push(`<table class="table"><thead><tr><th>#</th><th>Length</th><th>Revision</th><th>Type</th></tr></thead><tbody>`);
      s.certs.forEach((c, i) => out.push(`<tr><td>${i + 1}</td><td>${humanSize(c.Length)}</td><td>${hex(c.Revision, 4)}</td><td>${hex(c.CertificateType, 4)}</td></tr>`));
      out.push(`</tbody></table>`);
    }
    out.push(`</section>`);
  }

  // IAT summary
  if (pe.iat) {
    const t = pe.iat;
    out.push(`<section><h4 style="margin:0 0 .5rem 0;font-size:.9rem">Import Address Table (IAT)</h4><dl>`);
    out.push(dd("RVA", hex(t.rva, 8), "RVA of the runtime IAT used by the loader to place resolved addresses."));
    out.push(dd("Size", humanSize(t.size), "Total size of the IAT in bytes."));
    out.push(`</dl></section>`);
  }

  // Coverage map
  if (pe.coverage?.length) {
    out.push(`<section><h4 style="margin:0 0 .5rem 0;font-size:.9rem">Coverage map (file offsets)</h4>`);
    const cov = [...pe.coverage].sort((a, b) => a.off - b.off);
    out.push(`<table class="table"><thead><tr><th>#</th><th>Start (off)</th><th>End (off)</th><th>Size</th><th>Region</th></tr></thead><tbody>`);
    cov.forEach((c, i) => out.push(`<tr><td>${i + 1}</td><td>${hex(c.off, 8)}</td><td>${hex(c.end, 8)}</td><td>${humanSize(c.size)}</td><td>${safe(c.label)}</td></tr>`));
    out.push(`</tbody></table></section>`);
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
