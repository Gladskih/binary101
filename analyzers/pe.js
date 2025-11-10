"use strict";

import { humanSize, hex, ascii, runStrings, alignUp } from "../utils.js";

// PE constants used by parser and renderer
export const MACHINE = [
  [0x0000, "UNKNOWN"], [0x014c, "x86 (I386)"], [0x8664, "x86-64 (AMD64)"],
  [0x01c0, "ARM"], [0x01c4, "ARMv7 Thumb-2 (ARMNT)"], [0xaa64, "ARM64"], [0xa641, "ARM64EC"], [0xa64e, "ARM64X"],
  [0x0200, "IA-64"], [0x0166, "MIPS"], [0x0168, "MIPS16"], [0x01f0, "POWERPC"], [0x01f1, "POWERPCFP"],
  [0x9041, "M32R"], [0x01a2, "SH3"], [0x01a3, "SH3DSP"], [0x01a6, "SH4"], [0x01a8, "SH5"], [0x01c2, "ARMv7 (old)"],
  [0x0EBC, "EFI Byte Code"], [0x5032, "RISC-V32"], [0x5064, "RISC-V64"], [0x5128, "RISC-V128"]
];

export const SUBSYSTEMS = [
  [0, "Unknown"], [1, "Native"], [2, "Windows GUI"], [3, "Windows CUI"], [5, "OS/2 CUI"], [7, "POSIX CUI"],
  [9, "Windows CE GUI"], [10, "EFI Application"], [11, "EFI Boot Service Driver"], [12, "EFI Runtime Driver"],
  [13, "EFI ROM"], [14, "XBOX"], [16, "Windows Boot Application"]
];

export const CHAR_FLAGS = [
  [0x0001, "RELOCS_STRIPPED", "Relocations stripped from the file"],
  [0x0002, "EXECUTABLE_IMAGE", "Image is valid and can run"],
  [0x0004, "LINE_NUMS_STRIPPED", "COFF line numbers removed (deprecated)"],
  [0x0008, "LOCAL_SYMS_STRIPPED", "Local symbols removed (COFF)"],
  [0x0010, "AGGRESSIVE_WS_TRIM", "Aggressively trim working set (obsolete)"],
  [0x0020, "LARGE_ADDRESS_AWARE", "Image can handle >2GB addresses"],
  [0x0040, "BYTES_REVERSED_LO", "Little-endian byte ordering (obsolete)"],
  [0x0080, "32BIT_MACHINE", "Image is designed for a 32-bit machine"],
  [0x0100, "DEBUG_STRIPPED", "Debug info removed from file"],
  [0x0200, "REMOVABLE_RUN_FROM_SWAP", "Copy image to swap file if on removable media"],
  [0x0400, "NET_RUN_FROM_SWAP", "Copy image to swap file if on network"],
  [0x0800, "SYSTEM", "System file (kernel/driver)"],
  [0x1000, "DLL", "Dynamic-link library"],
  [0x2000, "UP_SYSTEM_ONLY", "Uni-processor machine only"],
  [0x8000, "BYTES_REVERSED_HI", "Big-endian byte ordering (obsolete)"],
];

export const DLL_FLAGS = [
  [0x0020, "HIGH_ENTROPY_VA", "Indicates 64-bit high-entropy ASLR support (PE32+)"],
  [0x0040, "DYNAMIC_BASE", "Image is relocatable (ASLR)"],
  [0x0080, "FORCE_INTEGRITY", "Code integrity checks are enforced"],
  [0x0100, "NX_COMPAT", "Image is compatible with DEP (no-execute)"],
  [0x0200, "NO_ISOLATION", "Isolation disabled (no SxS)"],
  [0x0400, "NO_SEH", "No structured exception handling"],
  [0x0800, "NO_BIND", "Do not bind to import addresses"],
  [0x1000, "APPCONTAINER", "Must execute in AppContainer"],
  [0x2000, "WDM_DRIVER", "WDM driver"],
  [0x4000, "GUARD_CF", "Control Flow Guard enabled"],
  [0x8000, "TERMINAL_SERVER_AWARE", "Terminal Server aware"],
];

export const DD_NAMES = [
  "EXPORT", "IMPORT", "RESOURCE", "EXCEPTION", "SECURITY", "BASERELOC", "DEBUG", "ARCHITECTURE",
  "GLOBALPTR", "TLS", "LOAD_CONFIG", "BOUND_IMPORT", "IAT", "DELAY_IMPORT", "CLR_RUNTIME", "RESERVED"
];

export const DD_TIPS = {
  EXPORT: "Export directory: function addresses and names exported by the image.",
  IMPORT: "Import directory: modules and symbols that this image depends on (link-time).",
  RESOURCE: "Resource directory: version, icons, dialogs, manifests, etc.",
  EXCEPTION: "Exception directory (.pdata): unwind info for x64 structured exception handling.",
  SECURITY: "Security directory: WIN_CERTIFICATE / Authenticode signatures (not mapped into memory).",
  BASERELOC: "Base relocation directory (.reloc): fixups applied when image is not loaded at preferred base.",
  DEBUG: "Debug directory: CodeView/RSDS pointers to PDBs, misc debug info.",
  TLS: "Thread Local Storage: per-thread data and optional TLS callbacks.",
  LOAD_CONFIG: "Load Configuration: security hardening structures (CFG, SEH tables, GS cookie).",
  IAT: "Import Address Table: resolved addresses loaded by the loader (runtime).",
  DELAY_IMPORT: "Delay-load import descriptors (resolved on first use).",
  CLR_RUNTIME: ".NET/CLR header for managed assemblies."
};

export const SEC_FLAG_TEXTS = [
  [0x00000020, "CNT_CODE"],
  [0x00000040, "CNT_INITIALIZED_DATA"],
  [0x00000080, "CNT_UNINITIALIZED_DATA"],
  [0x02000000, "DISCARDABLE"],
  [0x04000000, "NOT_CACHED"],
  [0x08000000, "NOT_PAGED"],
  [0x10000000, "SHARED"],
  [0x20000000, "EXECUTE"],
  [0x40000000, "READ"],
  [0x80000000, "WRITE"],
];

export const GUARD_FLAGS = [
  [0x00000100, "CF_INSTRUMENTED"],
  [0x00000200, "CF_WRITE_CHECKED"],
  [0x00000400, "CF_FUNCTION_TABLE_PRESENT"],
  [0x00000800, "SECURITY_COOKIE_UNUSED"],
  [0x00001000, "CF_LONGJUMP_TARGET"],
  [0x00004000, "CF_FUNCTION_TABLE_VALID"],
  [0x00008000, "CF_EXPORT_SUPPRESSION_INFO_PRESENT"],
  [0x00010000, "CF_ENABLE_EXPORT_SUPPRESSION"],
  [0x00020000, "CF_LONGJUMP_TABLE_PRESENT"],
];

export const peProbe = dv => dv.byteLength >= 0x40 && dv.getUint16(0, true) === 0x5a4d
  ? ({ e_lfanew: dv.getUint32(0x3c, true) }) : null;

export const mapMachine = m => MACHINE.find(([c]) => c === m)?.[1] || ("machine=" + hex(m, 4));

function makeRvaMapper(sections) {
  const spans = sections.map(s => {
    const va = s.virtualAddress >>> 0;
    const vs = Math.max(s.virtualSize >>> 0, s.sizeOfRawData >>> 0);
    const off = s.pointerToRawData >>> 0;
    return { vaEnd: (va + vs) >>> 0, va, off };
  });
  return rva => {
    rva >>> 0;
    for (const s of spans) { if (rva >= s.va && rva < s.vaEnd) return (s.off + (rva - s.va)) >>> 0; }
    return null;
  };
}

function shannonEntropy(u8) {
  if (!u8 || u8.length === 0) return 0;
  const freq = new Uint32Array(256);
  for (let i = 0; i < u8.length; i++) freq[u8[i]]++;
  let H = 0; const n = u8.length;
  for (let i = 0; i < 256; i++) {
    const f = freq[i]; if (!f) continue;
    const p = f / n; H -= p * Math.log2(p);
  }
  return H; // 0..8 bits/byte
}

export async function parsePe(file) {
  const head = new DataView(await file.slice(0, Math.min(file.size, 0x400)).arrayBuffer());
  const probe = peProbe(head); if (!probe) return null;
  const e_lfanew = probe.e_lfanew; if (e_lfanew == null || e_lfanew + 24 > file.size) return null;

  // DOS header
  const H = head;
  const dos = {
    e_magic: ascii(H, 0, 2),
    e_cblp: H.getUint16(0x02, true),
    e_cp: H.getUint16(0x04, true),
    e_crlc: H.getUint16(0x06, true),
    e_cparhdr: H.getUint16(0x08, true),
    e_minalloc: H.getUint16(0x0a, true),
    e_maxalloc: H.getUint16(0x0c, true),
    e_ss: H.getUint16(0x0e, true),
    e_sp: H.getUint16(0x10, true),
    e_csum: H.getUint16(0x12, true),
    e_ip: H.getUint16(0x14, true),
    e_cs: H.getUint16(0x16, true),
    e_lfarlc: H.getUint16(0x18, true),
    e_ovno: H.getUint16(0x1a, true),
    e_res: [H.getUint16(0x1c, true), H.getUint16(0x1e, true), H.getUint16(0x20, true), H.getUint16(0x22, true)],
    e_oemid: H.getUint16(0x24, true),
    e_oeminfo: H.getUint16(0x26, true),
    e_res2: Array.from({ length: 10 }, (_, i) => H.getUint16(0x28 + i * 2, true)),
    e_lfanew
  };
  let stub = { kind: "none", note: "" };
  if (e_lfanew > 0x40) {
    const len = Math.min(e_lfanew - 0x40, 64 * 1024);
    const u8 = new Uint8Array(await file.slice(0x40, 0x40 + len).arrayBuffer());
    const runs = runStrings(u8, 12);
    const classic = runs.find(s => /this program cannot be run in dos mode/i.test(s));
    if (classic) stub = { kind: "standard", note: "classic DOS message", strings: [classic] };
    else if (runs.length) stub = { kind: "non-standard", note: "printable text", strings: runs.slice(0, 4) };
  }
  dos.stub = stub;

  // PE signature + COFF
  const coffDV = new DataView(await file.slice(e_lfanew, e_lfanew + 24).arrayBuffer());
  const sig = String.fromCharCode(coffDV.getUint8(0)) + String.fromCharCode(coffDV.getUint8(1)) + String.fromCharCode(coffDV.getUint8(2)) + String.fromCharCode(coffDV.getUint8(3));
  if (sig !== "PE\0\0") return null;
  const coffOff = 4;
  const Machine = coffDV.getUint16(coffOff + 0, true);
  const NumberOfSections = coffDV.getUint16(coffOff + 2, true);
  const TimeDateStamp = coffDV.getUint32(coffOff + 4, true);
  const PointerToSymbolTable = coffDV.getUint32(coffOff + 8, true);
  const NumberOfSymbols = coffDV.getUint32(coffOff + 12, true);
  const SizeOfOptionalHeader = coffDV.getUint16(coffOff + 16, true);
  const Characteristics = coffDV.getUint16(coffOff + 18, true);

  // Optional header
  const optOff = e_lfanew + 24;
  const optDV = new DataView(await file.slice(optOff, optOff + Math.min(SizeOfOptionalHeader, 0x600)).arrayBuffer());
  let p = 0; const Magic = optDV.getUint16(p, true); p += 2;
  const isPlus = Magic === 0x20b, is32 = Magic === 0x10b;
  const LinkerMajor = optDV.getUint8(p++), LinkerMinor = optDV.getUint8(p++);
  const SizeOfCode = optDV.getUint32(p, true); p += 4;
  const SizeOfInitializedData = optDV.getUint32(p, true); p += 4;
  const SizeOfUninitializedData = optDV.getUint32(p, true); p += 4;
  const AddressOfEntryPoint = optDV.getUint32(p, true); p += 4;
  const BaseOfCode = optDV.getUint32(p, true); p += 4;
  let BaseOfData = is32 ? optDV.getUint32(p, true) : undefined; if (is32) p += 4;
  const ImageBase = isPlus ? Number(optDV.getBigUint64(p, true)) : optDV.getUint32(p, true); p += isPlus ? 8 : 4;
  const SectionAlignment = optDV.getUint32(p, true); p += 4;
  const FileAlignment = optDV.getUint32(p, true); p += 4;
  const OSVersionMajor = optDV.getUint16(p, true), OSVersionMinor = optDV.getUint16(p + 2, true); p += 4;
  const ImageVersionMajor = optDV.getUint16(p, true), ImageVersionMinor = optDV.getUint16(p + 2, true); p += 4;
  const SubsystemVersionMajor = optDV.getUint16(p, true), SubsystemVersionMinor = optDV.getUint16(p + 2, true); p += 4;
  const Win32VersionValue = optDV.getUint32(p, true); p += 4;
  const SizeOfImage = optDV.getUint32(p, true); p += 4;
  const SizeOfHeaders = optDV.getUint32(p, true); p += 4;
  const CheckSum = optDV.getUint32(p, true); p += 4;
  const Subsystem = optDV.getUint16(p, true); p += 2;
  const DllCharacteristics = optDV.getUint16(p, true); p += 2;
  const SizeOfStackReserve = isPlus ? Number(optDV.getBigUint64(p, true)) : optDV.getUint32(p, true); p += isPlus ? 8 : 4;
  const SizeOfStackCommit = isPlus ? Number(optDV.getBigUint64(p, true)) : optDV.getUint32(p, true); p += isPlus ? 8 : 4;
  const SizeOfHeapReserve = isPlus ? Number(optDV.getBigUint64(p, true)) : optDV.getUint32(p, true); p += isPlus ? 8 : 4;
  const SizeOfHeapCommit = isPlus ? Number(optDV.getBigUint64(p, true)) : optDV.getUint32(p, true); p += isPlus ? 8 : 4;
  const LoaderFlags = optDV.getUint32(p, true); p += 4;
  const NumberOfRvaAndSizes = optDV.getUint32(p, true); p += 4;

  const ddCount = Math.min(16, NumberOfRvaAndSizes, Math.floor((optDV.byteLength - p) / 8));
  const dataDirs = [];
  for (let i = 0; i < ddCount; i++) {
    const rva = optDV.getUint32(p + i * 8, true), size = optDV.getUint32(p + i * 8 + 4, true);
    dataDirs.push({ index: i, name: DD_NAMES[i] || "", rva, size });
  }

  // Sections
  const sectOff = optOff + SizeOfOptionalHeader;
  const sectDV = new DataView(await file.slice(sectOff, sectOff + NumberOfSections * 40).arrayBuffer());
  const sections = [];
  for (let i = 0; i < NumberOfSections; i++) {
    const b = i * 40; let name = "";
    for (let j = 0; j < 8; j++) { const c = sectDV.getUint8(b + j); if (c === 0) break; name += String.fromCharCode(c); }
    const virtualSize = sectDV.getUint32(b + 8, true), virtualAddress = sectDV.getUint32(b + 12, true);
    const sizeOfRawData = sectDV.getUint32(b + 16, true), pointerToRawData = sectDV.getUint32(b + 20, true);
    const characteristics = sectDV.getUint32(b + 36, true);
    sections.push({ name: name || "(unnamed)", virtualSize, virtualAddress, sizeOfRawData, pointerToRawData, characteristics });
  }
  const rvaToOff = makeRvaMapper(sections);

  // Overlay detection & image size checks
  let rawEnd = 0; for (const s of sections) rawEnd = Math.max(rawEnd, (s.pointerToRawData >>> 0) + (s.sizeOfRawData >>> 0));
  const overlaySize = file.size > rawEnd ? (file.size - rawEnd) : 0;
  let imageEnd = 0; for (const s of sections) imageEnd = Math.max(imageEnd, alignUp((s.virtualAddress >>> 0) + (s.virtualSize >>> 0), SectionAlignment >>> 0));
  const imageSizeMismatch = imageEnd !== (SizeOfImage >>> 0);

  // Debug: RSDS
  let rsds = null; {
    const dbg = dataDirs.find(d => d.name === "DEBUG");
    if (dbg?.rva && dbg.size >= 28) {
      const dbgOff = rvaToOff(dbg.rva);
      if (dbgOff != null) {
        const cnt = Math.min(16, Math.floor(dbg.size / 28));
        for (let i = 0; i < cnt; i++) {
          const o = dbgOff + i * 28;
          const ent = new DataView(await file.slice(o, o + 28).arrayBuffer());
          const typ = ent.getUint32(12, true), rawSize = ent.getUint32(16, true), rawPtr = ent.getUint32(20, true);
          if (typ === 2 && rawPtr && rawSize >= 24) {
            const dv = new DataView(await file.slice(rawPtr, rawPtr + rawSize).arrayBuffer());
            if (dv.getUint32(0, true) === 0x53445352) { // 'RSDS'
              const g0 = dv.getUint32(4, true), g1 = dv.getUint16(8, true), g2 = dv.getUint16(10, true);
              const g3 = new Uint8Array(await file.slice(rawPtr + 12, rawPtr + 20).arrayBuffer());
              const guid = `${hex(g0, 8).slice(2)}-${g1.toString(16).padStart(4, "0")}-${g2.toString(16).padStart(4, "0")}-${[...g3.slice(0, 2)].map(b => b.toString(16).padStart(2, "0")).join("")}-${[...g3.slice(2)].map(b => b.toString(16).padStart(2, "0")).join("")}`.toLowerCase();
              const age = new DataView(await file.slice(rawPtr + 20, rawPtr + 24).arrayBuffer()).getUint32(0, true);
              let pth = ""; {
                let pos = rawPtr + 24;
                for (;;) {
                  const chunk = new Uint8Array(await file.slice(pos, pos + 64).arrayBuffer());
                  const idx = chunk.findIndex(c => c === 0);
                  if (idx === -1) { pth += String.fromCharCode(...chunk); pos += 64; if (pos > file.size) break; }
                  else { if (idx > 0) pth += String.fromCharCode(...chunk.slice(0, idx)); break; }
                }
              }
              rsds = { guid, age, path: pth };
              break;
            }
          }
        }
      }
    }
  }

  // Load Config (subset with sanity)
  let loadcfg = null; {
    const lc = dataDirs.find(d => d.name === "LOAD_CONFIG");
    if (lc?.rva && lc.size >= 0x40) {
      const base = rvaToOff(lc.rva);
      if (base != null) {
        const dv = new DataView(await file.slice(base, base + Math.min(lc.size, 0x200)).arrayBuffer());
        const Size = dv.getUint32(0, true), TimeDateStamp = dv.getUint32(4, true);
        const Major = dv.getUint16(8, true), Minor = dv.getUint16(10, true);
        let SecurityCookie = 0, SEHandlerTable = 0, SEHandlerCount = 0, GuardCFFunctionTable = 0, GuardCFFunctionCount = 0, GuardFlags = 0;
        if (isPlus) {
          if (dv.byteLength >= 0x78) {
            SecurityCookie = Number(dv.getBigUint64(0x40, true));
            SEHandlerTable = Number(dv.getBigUint64(0x58, true));
            SEHandlerCount = dv.getUint32(0x60, true);
            GuardCFFunctionTable = Number(dv.getBigUint64(0x68, true));
            GuardCFFunctionCount = dv.getUint32(0x70, true);
            GuardFlags = dv.getUint32(0x74, true);
          }
        } else {
          if (dv.byteLength >= 0x54) {
            SecurityCookie = dv.getUint32(0x34, true);
            SEHandlerTable = dv.getUint32(0x40, true);
            SEHandlerCount = dv.getUint32(0x44, true);
            GuardCFFunctionTable = dv.getUint32(0x48, true);
            GuardCFFunctionCount = dv.getUint32(0x4C, true);
            GuardFlags = dv.getUint32(0x50, true);
          }
        }
        const saneCount = x => Number.isFinite(x) && x >= 0 && x <= 10_000_000 ? x : 0;
        loadcfg = {
          Size, TimeDateStamp, Major, Minor,
          SecurityCookie: SecurityCookie || 0,
          SEHandlerTable: SEHandlerTable || 0,
          SEHandlerCount: saneCount(SEHandlerCount),
          GuardCFFunctionTable: GuardCFFunctionTable || 0,
          GuardCFFunctionCount: saneCount(GuardCFFunctionCount),
          GuardFlags
        };
      }
    }
  }

  // Import table (existing robust parser)
  const impDir = dataDirs.find(d => d.name === "IMPORT");
  const imports = [];
  if (impDir?.rva) {
    const start = rvaToOff(impDir.rva);
    if (start != null) {
      const maxDesc = Math.max(1, Math.floor(impDir.size / 20));
      for (let i = 0; i < maxDesc; i++) {
        const off = start + i * 20;
        const desc = new DataView(await file.slice(off, off + 20).arrayBuffer());
        const OFT = desc.getUint32(0, true), TDS = desc.getUint32(4, true), Fwd = desc.getUint32(8, true), NameRVA = desc.getUint32(12, true), FT = desc.getUint32(16, true);
        if (OFT === 0 && TDS === 0 && Fwd === 0 && NameRVA === 0 && FT === 0) break;
        const nameOff = rvaToOff(NameRVA); let dll = "";
        if (nameOff != null) { const dv = new DataView(await file.slice(nameOff, nameOff + 256).arrayBuffer()); dll = ascii(dv, 0, 256); }
        const thunkRva = OFT || FT; const thunkOff = rvaToOff(thunkRva); const funcs = [];
        if (thunkOff != null) {
          if (isPlus) {
            for (let t = 0;; t += 8) {
              const dv = new DataView(await file.slice(thunkOff + t, thunkOff + t + 8).arrayBuffer());
              const val = dv.getBigUint64(0, true);
              if (val === 0n) break;
              if ((val & 0x8000000000000000n) !== 0n) { funcs.push({ ordinal: Number(val & 0xffffn) }); }
              else {
                const rva = Number(val & 0xffffffffn);
                const hnOff = rvaToOff(rva);
                if (hnOff != null) {
                  const hint = new DataView(await file.slice(hnOff, hnOff + 2).arrayBuffer()).getUint16(0, true);
                  let s = ""; { let pos = hnOff + 2; for (;;) {
                    const chunk = new Uint8Array(await file.slice(pos, pos + 64).arrayBuffer()); const idx = chunk.findIndex(c => c === 0);
                    if (idx === -1) { s += String.fromCharCode(...chunk); pos += 64; if (pos > file.size) break; }
                    else { if (idx) s += String.fromCharCode(...chunk.slice(0, idx)); break; }
                  }}
                  funcs.push({ hint, name: s });
                } else funcs.push({ name: "<bad RVA>" });
              }
            }
          } else {
            for (let t = 0;; t += 4) {
              const dv = new DataView(await file.slice(thunkOff + t, thunkOff + t + 4).arrayBuffer());
              const val = dv.getUint32(0, true);
              if (val === 0) break;
              if ((val & 0x80000000) !== 0) { funcs.push({ ordinal: (val & 0xffff) }); }
              else {
                const hnOff = rvaToOff(val);
                if (hnOff != null) {
                  const hint = new DataView(await file.slice(hnOff, hnOff + 2).arrayBuffer()).getUint16(0, true);
                  let s = ""; { let pos = hnOff + 2; for (;;) {
                    const chunk = new Uint8Array(await file.slice(pos, pos + 64).arrayBuffer()); const idx = chunk.findIndex(c => c === 0);
                    if (idx === -1) { s += String.fromCharCode(...chunk); pos += 64; if (pos > file.size) break; }
                    else { if (idx) s += String.fromCharCode(...chunk.slice(0, idx)); break; }
                  }}
                  funcs.push({ hint, name: s });
                } else funcs.push({ name: "<bad RVA>" });
              }
            }
          }
        }
        imports.push({ dll, functions: funcs });
      }
    }
  }

  // Export directory
  let exports = null; {
    const ex = dataDirs.find(d => d.name === "EXPORT");
    if (ex?.rva && ex.size >= 40) {
      const off = rvaToOff(ex.rva);
      if (off != null) {
        const dv = new DataView(await file.slice(off, off + Math.min(ex.size, 0x200)).arrayBuffer());
        const Characteristics = dv.getUint32(0, true);
        const TimeDateStamp = dv.getUint32(4, true);
        const MajorVersion = dv.getUint16(8, true), MinorVersion = dv.getUint16(10, true);
        const NameRVA = dv.getUint32(12, true);
        const Base = dv.getUint32(16, true);
        const NumberOfFunctions = dv.getUint32(20, true);
        const NumberOfNames = dv.getUint32(24, true);
        const AddressOfFunctions = dv.getUint32(28, true);
        const AddressOfNames = dv.getUint32(32, true);
        const AddressOfNameOrdinals = dv.getUint32(36, true);

        let dllName = ""; const nmOff = rvaToOff(NameRVA);
        if (nmOff != null) dllName = ascii(new DataView(await file.slice(nmOff, nmOff + 256).arrayBuffer()), 0, 256);

        const funcs = [];
        const eatOff = rvaToOff(AddressOfFunctions);
        const entOff = rvaToOff(AddressOfNames);
        const enoOff = rvaToOff(AddressOfNameOrdinals);
        if (eatOff != null && NumberOfFunctions) {
          const eat = new DataView(await file.slice(eatOff, eatOff + NumberOfFunctions * 4).arrayBuffer());
          // Optionally resolve names
          let ent = null, eno = null;
          if (entOff != null && enoOff != null && NumberOfNames) {
            ent = new DataView(await file.slice(entOff, entOff + NumberOfNames * 4).arrayBuffer());
            eno = new DataView(await file.slice(enoOff, enoOff + NumberOfNames * 2).arrayBuffer());
          }
          const nameMap = new Map();
          if (ent && eno) {
            for (let i = 0; i < NumberOfNames; i++) {
              const rva = ent.getUint32(i * 4, true);
              const no = eno.getUint16(i * 2, true);
              const so = rvaToOff(rva);
              let nm = ""; if (so != null) nm = ascii(new DataView(await file.slice(so, so + 256).arrayBuffer()), 0, 256);
              nameMap.set(no, nm);
            }
          }
          for (let ord = 0; ord < NumberOfFunctions; ord++) {
            const rva = eat.getUint32(ord * 4, true);
            const isForwarder = rva >= ex.rva && rva < (ex.rva + ex.size);
            let forwarder = null;
            if (isForwarder) {
              const fOff = rvaToOff(rva);
              if (fOff != null) forwarder = ascii(new DataView(await file.slice(fOff, fOff + 256).arrayBuffer()), 0, 256);
            }
            funcs.push({ ordinal: Base + ord, name: nameMap.get(ord) || null, rva, forwarder });
          }
        }
        exports = { dllName, Characteristics, TimeDateStamp, MajorVersion, MinorVersion, Base, NumberOfFunctions, NumberOfNames, AddressOfFunctions, AddressOfNames, AddressOfNameOrdinals, entries: funcs };
      }
    }
  }

  // TLS directory (basic)
  let tls = null; {
    const td = dataDirs.find(d => d.name === "TLS");
    if (td?.rva) {
      const off = rvaToOff(td.rva);
      if (off != null) {
        if (isPlus) {
          const dv = new DataView(await file.slice(off, off + 0x30).arrayBuffer());
          const StartAddressOfRawData = Number(dv.getBigUint64(0, true));
          const EndAddressOfRawData = Number(dv.getBigUint64(8, true));
          const AddressOfIndex = Number(dv.getBigUint64(16, true));
          const AddressOfCallBacks = Number(dv.getBigUint64(24, true));
          const SizeOfZeroFill = dv.getUint32(32, true);
          const Characteristics = dv.getUint32(36, true);
          let CallbackCount = 0;
          if (AddressOfCallBacks) {
            // We cannot dereference VA, but for some linkers this points into image VA range → try RVA mapping
            const rva = (AddressOfCallBacks - ImageBase) >>> 0;
            const po = rvaToOff(rva);
            if (po != null) {
              for (let i = 0; i < 1024; i++) { // hard cap
                const ptr = new DataView(await file.slice(po + i * 8, po + i * 8 + 8).arrayBuffer()).getBigUint64(0, true);
                if (ptr === 0n) { CallbackCount = i; break; }
              }
            }
          }
          tls = { StartAddressOfRawData, EndAddressOfRawData, AddressOfIndex, AddressOfCallBacks, SizeOfZeroFill, Characteristics, CallbackCount };
        } else {
          const dv = new DataView(await file.slice(off, off + 0x18).arrayBuffer());
          const StartAddressOfRawData = dv.getUint32(0, true);
          const EndAddressOfRawData = dv.getUint32(4, true);
          const AddressOfIndex = dv.getUint32(8, true);
          const AddressOfCallBacks = dv.getUint32(12, true);
          const SizeOfZeroFill = dv.getUint32(16, true);
          const Characteristics = dv.getUint32(20, true);
          let CallbackCount = 0;
          if (AddressOfCallBacks) {
            const po = rvaToOff(AddressOfCallBacks);
            if (po != null) {
              for (let i = 0; i < 2048; i++) { // 32-bit entries
                const ptr = new DataView(await file.slice(po + i * 4, po + i * 4 + 4).arrayBuffer()).getUint32(0, true);
                if (ptr === 0) { CallbackCount = i; break; }
              }
            }
          }
          tls = { StartAddressOfRawData, EndAddressOfRawData, AddressOfIndex, AddressOfCallBacks, SizeOfZeroFill, Characteristics, CallbackCount };
        }
      }
    }
  }

  // Base relocations (summary)
  let reloc = null; {
    const rd = dataDirs.find(d => d.name === "BASERELOC");
    if (rd?.rva && rd.size >= 8) {
      const start = rvaToOff(rd.rva);
      if (start != null) {
        let off = start; const end = start + rd.size; const blocks = [];
        while (off + 8 <= end) {
          const dv = new DataView(await file.slice(off, off + 8).arrayBuffer());
          const VirtualAddress = dv.getUint32(0, true), SizeOfBlock = dv.getUint32(4, true);
          if (VirtualAddress === 0 || SizeOfBlock < 8) break;
          const entryCount = Math.floor((SizeOfBlock - 8) / 2);
          blocks.push({ VirtualAddress, SizeOfBlock, entryCount });
          off += SizeOfBlock;
        }
        const totalEntries = blocks.reduce((a, b) => a + b.entryCount, 0);
        reloc = { blocks, totalEntries };
      }
    }
  }

  // Section entropies
  for (const s of sections) {
    const { pointerToRawData: pr, sizeOfRawData: sz } = s;
    if (pr && sz) {
      const u8 = new Uint8Array(await file.slice(pr, pr + sz).arrayBuffer());
      s.entropy = shannonEntropy(u8);
    } else { s.entropy = 0; }
  }

  return {
    dos, signature: "PE",
    coff: { Machine, NumberOfSections, TimeDateStamp, PointerToSymbolTable, NumberOfSymbols, SizeOfOptionalHeader, Characteristics },
    opt: { Magic, isPlus, is32, LinkerMajor, LinkerMinor, SizeOfCode, SizeOfInitializedData, SizeOfUninitializedData, AddressOfEntryPoint, BaseOfCode, BaseOfData, ImageBase, SectionAlignment, FileAlignment, OSVersionMajor, OSVersionMinor, ImageVersionMajor, ImageVersionMinor, SubsystemVersionMajor, SubsystemVersionMinor, Win32VersionValue, SizeOfImage, SizeOfHeaders, CheckSum, Subsystem, DllCharacteristics, SizeOfStackReserve, SizeOfStackCommit, SizeOfHeapReserve, SizeOfHeapCommit, LoaderFlags, NumberOfRvaAndSizes },
    dirs: dataDirs, sections, rvaToOff, imports, rsds, loadcfg, exports, tls, reloc,
    overlaySize, imageEnd, imageSizeMismatch,
    hasCert: !!(dataDirs.find(d => d.name === "SECURITY")?.size)
  };
}

