"use strict";

import { toHex32, readAsciiString, collectPrintableRuns, alignUpTo } from "../utils.js";
import { MACHINE, DD_NAMES } from "./pe-constants.js";

export const peProbe = dataView =>
  dataView.byteLength >= 0x40 && dataView.getUint16(0, true) === 0x5a4d
    ? { e_lfanew: dataView.getUint32(0x3c, true) }
    : null;

export const mapMachine = machineCode =>
  MACHINE.find(([code]) => code === machineCode)?.[1] || "machine=" + toHex32(machineCode, 4);

function createRvaToOffsetMapper(sections) {
  const spans = sections.map(section => {
    const virtualAddress = section.virtualAddress >>> 0;
    const virtualSize = Math.max(section.virtualSize >>> 0, section.sizeOfRawData >>> 0);
    const fileOffset = section.pointerToRawData >>> 0;
    return { vaStart: virtualAddress, vaEnd: (virtualAddress + virtualSize) >>> 0, fileOffset };
  });
  return relativeVirtualAddress => {
    const normalized = relativeVirtualAddress >>> 0;
    for (const span of spans) {
      if (normalized >= span.vaStart && normalized < span.vaEnd) {
        return (span.fileOffset + (normalized - span.vaStart)) >>> 0;
      }
    }
    return null;
  };
}

function shannonEntropy(bytes) {
  if (!bytes || bytes.length === 0) return 0;
  const freq = new Uint32Array(256);
  for (let index = 0; index < bytes.length; index++) freq[bytes[index]]++;
  let entropy = 0;
  const totalCount = bytes.length;
  for (let i = 0; i < 256; i++) {
    const count = freq[i];
    if (!count) continue;
    const probability = count / totalCount;
    entropy -= probability * Math.log2(probability);
  }
  return entropy;
}

function base64FromU8(u8) {
  let s = "";
  const chunk = 0x8000;
  for (let i = 0; i < u8.length; i += chunk) {
    s += String.fromCharCode(...u8.subarray(i, Math.min(i + chunk, u8.length)));
  }
  try { return btoa(s); } catch { return ""; }
}

async function parseDosHeaderAndStub(file, headView, peHeaderOffset) {
  const dos = {
    e_magic: readAsciiString(headView, 0, 2),
    e_cblp: headView.getUint16(0x02, true),
    e_cp: headView.getUint16(0x04, true),
    e_crlc: headView.getUint16(0x06, true),
    e_cparhdr: headView.getUint16(0x08, true),
    e_minalloc: headView.getUint16(0x0a, true),
    e_maxalloc: headView.getUint16(0x0c, true),
    e_ss: headView.getUint16(0x0e, true),
    e_sp: headView.getUint16(0x10, true),
    e_csum: headView.getUint16(0x12, true),
    e_ip: headView.getUint16(0x14, true),
    e_cs: headView.getUint16(0x16, true),
    e_lfarlc: headView.getUint16(0x18, true),
    e_ovno: headView.getUint16(0x1a, true),
    e_res: [headView.getUint16(0x1c, true), headView.getUint16(0x1e, true), headView.getUint16(0x20, true), headView.getUint16(0x22, true)],
    e_oemid: headView.getUint16(0x24, true),
    e_oeminfo: headView.getUint16(0x26, true),
    e_res2: Array.from({ length: 10 }, (_, index) => headView.getUint16(0x28 + index * 2, true)),
    e_lfanew: peHeaderOffset
  };
  let stub = { kind: "none", note: "" };
  if (peHeaderOffset > 0x40) {
    const stubLength = Math.min(peHeaderOffset - 0x40, 64 * 1024);
    const stubBytes = new Uint8Array(await file.slice(0x40, 0x40 + stubLength).arrayBuffer());
    const printableRuns = collectPrintableRuns(stubBytes, 12);
    const classicMessage = printableRuns.find(text => /this program cannot be run in dos mode/i.test(text));
    if (classicMessage) stub = { kind: "standard", note: "classic DOS message", strings: [classicMessage] };
    else if (printableRuns.length) stub = { kind: "non-standard", note: "printable text", strings: printableRuns.slice(0, 4) };
  }
  dos.stub = stub;
  return dos;
}

async function parseCoffHeader(file, peHeaderOffset) {
  const headerView = new DataView(await file.slice(peHeaderOffset, peHeaderOffset + 24).arrayBuffer());
  const signature =
    String.fromCharCode(headerView.getUint8(0)) +
    String.fromCharCode(headerView.getUint8(1)) +
    String.fromCharCode(headerView.getUint8(2)) +
    String.fromCharCode(headerView.getUint8(3));
  if (signature !== "PE\0\0") return null;
  const coffOffset = 4;
  const Machine = headerView.getUint16(coffOffset + 0, true);
  const NumberOfSections = headerView.getUint16(coffOffset + 2, true);
  const TimeDateStamp = headerView.getUint32(coffOffset + 4, true);
  const PointerToSymbolTable = headerView.getUint32(coffOffset + 8, true);
  const NumberOfSymbols = headerView.getUint32(coffOffset + 12, true);
  const SizeOfOptionalHeader = headerView.getUint16(coffOffset + 16, true);
  const Characteristics = headerView.getUint16(coffOffset + 18, true);
  return { Machine, NumberOfSections, TimeDateStamp, PointerToSymbolTable, NumberOfSymbols, SizeOfOptionalHeader, Characteristics };
}

async function parseOptionalHeaderAndDirectories(file, peHeaderOffset, sizeOfOptionalHeader) {
  const optionalHeaderOffset = peHeaderOffset + 24;
  const optionalHeaderView = new DataView(await file.slice(optionalHeaderOffset, optionalHeaderOffset + Math.min(sizeOfOptionalHeader, 0x600)).arrayBuffer());
  let position = 0;
  const Magic = optionalHeaderView.getUint16(position, true); position += 2;
  const isPlus = Magic === 0x20b, is32 = Magic === 0x10b;
  const LinkerMajor = optionalHeaderView.getUint8(position++), LinkerMinor = optionalHeaderView.getUint8(position++);
  const SizeOfCode = optionalHeaderView.getUint32(position, true); position += 4;
  const SizeOfInitializedData = optionalHeaderView.getUint32(position, true); position += 4;
  const SizeOfUninitializedData = optionalHeaderView.getUint32(position, true); position += 4;
  const AddressOfEntryPoint = optionalHeaderView.getUint32(position, true); position += 4;
  const BaseOfCode = optionalHeaderView.getUint32(position, true); position += 4;
  let BaseOfData = is32 ? optionalHeaderView.getUint32(position, true) : undefined;
  if (is32) position += 4;
  const ImageBase = isPlus ? Number(optionalHeaderView.getBigUint64(position, true)) : optionalHeaderView.getUint32(position, true);
  position += isPlus ? 8 : 4;
  const SectionAlignment = optionalHeaderView.getUint32(position, true); position += 4;
  const FileAlignment = optionalHeaderView.getUint32(position, true); position += 4;
  const OSVersionMajor = optionalHeaderView.getUint16(position, true), OSVersionMinor = optionalHeaderView.getUint16(position + 2, true);
  position += 4;
  const ImageVersionMajor = optionalHeaderView.getUint16(position, true), ImageVersionMinor = optionalHeaderView.getUint16(position + 2, true);
  position += 4;
  const SubsystemVersionMajor = optionalHeaderView.getUint16(position, true), SubsystemVersionMinor = optionalHeaderView.getUint16(position + 2, true);
  position += 4;
  const Win32VersionValue = optionalHeaderView.getUint32(position, true);
  position += 4;
  const SizeOfImage = optionalHeaderView.getUint32(position, true);
  position += 4;
  const SizeOfHeaders = optionalHeaderView.getUint32(position, true);
  position += 4;
  const CheckSum = optionalHeaderView.getUint32(position, true);
  position += 4;
  const Subsystem = optionalHeaderView.getUint16(position, true);
  position += 2;
  const DllCharacteristics = optionalHeaderView.getUint16(position, true);
  position += 2;
  const SizeOfStackReserve = isPlus ? Number(optionalHeaderView.getBigUint64(position, true)) : optionalHeaderView.getUint32(position, true);
  position += isPlus ? 8 : 4;
  const SizeOfStackCommit = isPlus ? Number(optionalHeaderView.getBigUint64(position, true)) : optionalHeaderView.getUint32(position, true);
  position += isPlus ? 8 : 4;
  const SizeOfHeapReserve = isPlus ? Number(optionalHeaderView.getBigUint64(position, true)) : optionalHeaderView.getUint32(position, true);
  position += isPlus ? 8 : 4;
  const SizeOfHeapCommit = isPlus ? Number(optionalHeaderView.getBigUint64(position, true)) : optionalHeaderView.getUint32(position, true);
  position += isPlus ? 8 : 4;
  const LoaderFlags = optionalHeaderView.getUint32(position, true);
  position += 4;
  const NumberOfRvaAndSizes = optionalHeaderView.getUint32(position, true);
  position += 4;
  const ddStartRel = position;
  const ddCount = Math.min(16, NumberOfRvaAndSizes, Math.floor((optionalHeaderView.byteLength - position) / 8));
  const dataDirs = [];
  for (let index = 0; index < ddCount; index++) {
    const entryOffset = position + index * 8;
    const rva = optionalHeaderView.getUint32(entryOffset, true);
    const size = optionalHeaderView.getUint32(entryOffset + 4, true);
    dataDirs.push({ index, name: DD_NAMES[index] || "", rva, size });
  }
  const opt = {
    Magic,
    isPlus,
    is32,
    LinkerMajor,
    LinkerMinor,
    SizeOfCode,
    SizeOfInitializedData,
    SizeOfUninitializedData,
    AddressOfEntryPoint,
    BaseOfCode,
    BaseOfData,
    ImageBase,
    SectionAlignment,
    FileAlignment,
    OSVersionMajor,
    OSVersionMinor,
    ImageVersionMajor,
    ImageVersionMinor,
    SubsystemVersionMajor,
    SubsystemVersionMinor,
    Win32VersionValue,
    SizeOfImage,
    SizeOfHeaders,
    CheckSum,
    Subsystem,
    DllCharacteristics,
    SizeOfStackReserve,
    SizeOfStackCommit,
    SizeOfHeapReserve,
    SizeOfHeapCommit,
    LoaderFlags,
    NumberOfRvaAndSizes
  };
  return { optOff: optionalHeaderOffset, ddStartRel, ddCount, dataDirs, opt };
}

async function parseSectionHeaders(file, optionalHeaderOffset, sizeOfOptionalHeader, numberOfSections) {
  const sectionHeadersOffset = optionalHeaderOffset + sizeOfOptionalHeader;
  const sectionHeadersView = new DataView(await file.slice(sectionHeadersOffset, sectionHeadersOffset + numberOfSections * 40).arrayBuffer());
  const sections = [];
  for (let sectionIndex = 0; sectionIndex < numberOfSections; sectionIndex++) {
    const baseOffset = sectionIndex * 40;
    let name = "";
    for (let nameIndex = 0; nameIndex < 8; nameIndex++) {
      const codePoint = sectionHeadersView.getUint8(baseOffset + nameIndex);
      if (codePoint === 0) break;
      name += String.fromCharCode(codePoint);
    }
    const virtualSize = sectionHeadersView.getUint32(baseOffset + 8, true);
    const virtualAddress = sectionHeadersView.getUint32(baseOffset + 12, true);
    const sizeOfRawData = sectionHeadersView.getUint32(baseOffset + 16, true);
    const pointerToRawData = sectionHeadersView.getUint32(baseOffset + 20, true);
    const characteristics = sectionHeadersView.getUint32(baseOffset + 36, true);
    sections.push({
      name: name || "(unnamed)",
      virtualSize,
      virtualAddress,
      sizeOfRawData,
      pointerToRawData,
      characteristics
    });
  }
  const rvaToOff = createRvaToOffsetMapper(sections);
  return { sections, rvaToOff, sectOff: sectionHeadersOffset };
}

function buildCoverage(fileSize, peHeaderOffset, coff, optionalHeaderOffset, ddStartRel, ddCount, sectionHeadersOffset, sections, sectionAlignment, sizeOfImage) {
  const coverage = [];
  const addCov = (label, off, size) => {
    if (!Number.isFinite(off) || !Number.isFinite(size) || off < 0 || size <= 0) return;
    coverage.push({ label, off: off >>> 0, end: (off >>> 0) + (size >>> 0), size: size >>> 0 });
  };
  addCov("DOS header + stub", 0, Math.min(fileSize, Math.max(64, peHeaderOffset)));
  addCov("PE signature + COFF", peHeaderOffset, 24);
  addCov("Optional header", optionalHeaderOffset, coff.SizeOfOptionalHeader);
  addCov("Data directories", optionalHeaderOffset + ddStartRel, ddCount * 8);
  addCov("Section headers", sectionHeadersOffset, coff.NumberOfSections * 40);
  let rawEnd = 0;
  for (const section of sections) {
    const endOfSectionData = (section.pointerToRawData >>> 0) + (section.sizeOfRawData >>> 0);
    rawEnd = Math.max(rawEnd, endOfSectionData);
  }
  const overlaySize = fileSize > rawEnd ? fileSize - rawEnd : 0;
  let imageEnd = 0;
  for (const section of sections) {
    const endOfSectionImage = (section.virtualAddress >>> 0) + (section.virtualSize >>> 0);
    imageEnd = Math.max(imageEnd, alignUpTo(endOfSectionImage, sectionAlignment >>> 0));
  }
  const imageSizeMismatch = imageEnd !== (sizeOfImage >>> 0);
  if (overlaySize > 0) {
    addCov("Overlay (data after last section)", rawEnd, overlaySize);
  }
  for (const section of sections) addCov(`Section ${section.name} (raw)`, section.pointerToRawData, section.sizeOfRawData);
  return { coverage, addCov, overlaySize, imageEnd, imageSizeMismatch };
}

async function addSectionEntropies(file, sections) {
  for (const section of sections) {
    const { pointerToRawData, sizeOfRawData } = section;
    if (pointerToRawData && sizeOfRawData) {
      const bytes = new Uint8Array(await file.slice(pointerToRawData, pointerToRawData + sizeOfRawData).arrayBuffer());
      section.entropy = shannonEntropy(bytes);
    } else {
      section.entropy = 0;
    }
  }
}

export async function parsePe(file) {
  const head = new DataView(await file.slice(0, Math.min(file.size, 0x400)).arrayBuffer());
  const probe = peProbe(head);
  if (!probe) return null;
  const e_lfanew = probe.e_lfanew;
  if (e_lfanew == null || e_lfanew + 24 > file.size) return null;
  const dos = await parseDosHeaderAndStub(file, head, e_lfanew);
  const coff = await parseCoffHeader(file, e_lfanew);
  if (!coff) return null;
  const optional = await parseOptionalHeaderAndDirectories(file, e_lfanew, coff.SizeOfOptionalHeader);
  const { optOff, ddStartRel, ddCount, dataDirs, opt } = optional;
  const sectInfo = await parseSectionHeaders(file, optOff, coff.SizeOfOptionalHeader, coff.NumberOfSections);
  const { sections, rvaToOff, sectOff } = sectInfo;
  const coverageInfo = buildCoverage(file.size, e_lfanew, coff, optOff, ddStartRel, ddCount, sectOff, sections, opt.SectionAlignment, opt.SizeOfImage);
  const { coverage, addCov, overlaySize, imageEnd, imageSizeMismatch } = coverageInfo;
  const { isPlus, ImageBase } = opt;
  let entrySection = null;
  if (opt.AddressOfEntryPoint) {
    const entryRva = opt.AddressOfEntryPoint >>> 0;
    for (let index = 0; index < sections.length; index++) {
      const section = sections[index];
      const start = section.virtualAddress >>> 0;
      const end = (start + (section.virtualSize >>> 0)) >>> 0;
      if (entryRva >= start && entryRva < end) {
        entrySection = { name: section.name, index };
        break;
      }
    }
  }

  // Debug: RSDS
  let rsds = null; {
    const dbg = dataDirs.find(d => d.name === "DEBUG");
    if (dbg?.rva && dbg.size >= 28) {
      const dbgOff = rvaToOff(dbg.rva);
      if (dbgOff != null) {
        addCov("DEBUG directory", dbgOff, dbg.size);
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
  const guid = `${toHex32(g0, 8).slice(2)}-${g1.toString(16).padStart(4, "0")}-${g2.toString(16).padStart(4, "0")}-${[...g3.slice(0, 2)].map(b => b.toString(16).padStart(2, "0")).join("")}-${[...g3.slice(2)].map(b => b.toString(16).padStart(2, "0")).join("")}`.toLowerCase();
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
        addCov("LOAD_CONFIG", base, lc.size);
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
      addCov("IMPORT directory", start, impDir.size);
      const maxDesc = Math.max(1, Math.floor(impDir.size / 20));
      for (let i = 0; i < maxDesc; i++) {
        const off = start + i * 20;
        const desc = new DataView(await file.slice(off, off + 20).arrayBuffer());
        const OFT = desc.getUint32(0, true), TDS = desc.getUint32(4, true), Fwd = desc.getUint32(8, true), NameRVA = desc.getUint32(12, true), FT = desc.getUint32(16, true);
        if (OFT === 0 && TDS === 0 && Fwd === 0 && NameRVA === 0 && FT === 0) break;
        const nameOff = rvaToOff(NameRVA);
        let dll = "";
        if (nameOff != null) {
          const dv = new DataView(await file.slice(nameOff, nameOff + 256).arrayBuffer());
          dll = readAsciiString(dv, 0, 256);
        }
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
        addCov("EXPORT directory", off, ex.size);
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

        let dllName = "";
        const nmOff = rvaToOff(NameRVA);
        if (nmOff != null) {
          const nameView = new DataView(await file.slice(nmOff, nmOff + 256).arrayBuffer());
          dllName = readAsciiString(nameView, 0, 256);
        }

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
          let nm = "";
          if (so != null) {
            const nameView = new DataView(await file.slice(so, so + 256).arrayBuffer());
            nm = readAsciiString(nameView, 0, 256);
          }
          nameMap.set(no, nm);
            }
          }
          for (let ord = 0; ord < NumberOfFunctions; ord++) {
            const rva = eat.getUint32(ord * 4, true);
            const isForwarder = rva >= ex.rva && rva < (ex.rva + ex.size);
            let forwarder = null;
            if (isForwarder) {
            const fOff = rvaToOff(rva);
            if (fOff != null) {
              const forwardView = new DataView(await file.slice(fOff, fOff + 256).arrayBuffer());
              forwarder = readAsciiString(forwardView, 0, 256);
            }
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
        addCov("TLS directory", off, Math.min(td.size || (isPlus ? 0x30 : 0x18), isPlus ? 0x30 : 0x18));
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
        addCov("BASERELOC (.reloc)", start, rd.size);
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

  await addSectionEntropies(file, sections);

  // Resource directory (summary)
  let resources = null; {
    const rs = dataDirs.find(d => d.name === "RESOURCE");
    if (rs?.rva && rs.size >= 16) {
      const base = rvaToOff(rs.rva);
      if (base != null) {
        addCov("RESOURCE directory", base, rs.size);
        const limitStart = base, limitEnd = base + rs.size;
        const view = async (off, len) => new DataView(await file.slice(off, off + len).arrayBuffer());
        const u16 = (dv, off) => dv.getUint16(off, true);
        const u32 = (dv, off) => dv.getUint32(off, true);
        const readUcs2 = async rel => {
          const so = base + rel; if (so + 2 > limitEnd) return "";
          const dv = await view(so, 2); const len = u16(dv, 0);
          const b = new Uint8Array(await file.slice(so + 2, Math.min(limitEnd, so + 2 + len * 2)).arrayBuffer());
          // naive UCS-2LE → ASCII
          let s = ""; for (let i = 0; i + 1 < b.length; i += 2) { const ch = b[i] | (b[i + 1] << 8); if (ch === 0) break; s += String.fromCharCode(ch); }
          return s;
        };
        const knownType = id => ({
          1: "CURSOR", 2: "BITMAP", 3: "ICON", 4: "MENU", 5: "DIALOG", 6: "STRING", 7: "FONTDIR", 8: "FONT", 9: "ACCELERATOR",
          10: "RCDATA", 11: "MESSAGETABLE", 12: "GROUP_CURSOR", 14: "GROUP_ICON", 16: "VERSION", 17: "DLGINCLUDE", 19: "PLUGPLAY",
          20: "VXD", 21: "ANICURSOR", 22: "ANIICON", 23: "HTML", 24: "MANIFEST"
        })[id] || null;
        const isInside = off => off >= limitStart && off < limitEnd;
        const seen = new Set();
        const parseDir = async rel => {
          const off = base + rel; if (!isInside(off + 16)) return null;
          const dv = await view(off, 16);
          const Named = u16(dv, 12); const Ids = u16(dv, 14);
          const count = Named + Ids;
          const entriesOff = off + 16;
          const entries = [];
          for (let i = 0; i < count; i++) {
            const e = await view(entriesOff + i * 8, 8);
            const Name = u32(e, 0); const OffsetToData = u32(e, 4);
            const nameIsString = (Name & 0x80000000) !== 0;
            const subdir = (OffsetToData & 0x80000000) !== 0;
            let name = null, id = null;
            if (nameIsString) { name = await readUcs2(Name & 0x7fffffff); }
            else { id = Name & 0xffff; }
            entries.push({ name, id, subdir, target: OffsetToData & 0x7fffffff });
          }
          return { Named, Ids, entries };
        };
        const countLeaves = async rel => {
          const key = "D" + rel; if (seen.has(key)) return 0; seen.add(key);
          const dir = await parseDir(rel); if (!dir) return 0; let total = 0;
          for (const e of dir.entries) {
            if (e.subdir) total += await countLeaves(e.target);
            else total++;
          }
          return total;
        };
        const root = await parseDir(0);
        if (root) {
          // Build map of RT_ICON id -> {rva,size} for GROUP_ICON previews
          const iconIndex = new Map();
          for (const t of root.entries) {
            if (t.id === 3 && t.subdir) { // RT_ICON
              const nameDir = await parseDir(t.target);
              if (nameDir) {
                for (const n of nameDir.entries) {
                  if (!n.subdir) continue;
                  const langDir = await parseDir(n.target);
                  if (langDir) {
                    const leaf = langDir.entries.find(le => !le.subdir);
                    if (leaf) {
                      const deo2 = base + leaf.target;
                      if (isInside(deo2 + 16)) {
                        const dv2 = await view(deo2, 16);
                        const rva2 = u32(dv2, 0);
                        const sz2 = u32(dv2, 4);
                        if (n.id != null) iconIndex.set(n.id, { rva: rva2, size: sz2 });
                      }
                    }
                  }
                }
              }
            }
          }
          const top = [];
          const detail = [];
          for (const e of root.entries) {
            // Top-level entry corresponds to type
            let typeName = e.id != null ? (knownType(e.id) || `TYPE_${e.id}`) : (e.name || "(named)");
            let leafCount = 0; if (e.subdir) leafCount = await countLeaves(e.target);
            top.push({ typeName, kind: e.id != null ? "id" : "name", leafCount });
            if (e.subdir) {
              const nameDir = await parseDir(e.target);
              if (nameDir) {
                const entries = [];
                for (const nent of nameDir.entries) {
                  const child = { id: nent.id ?? null, name: nent.name ?? null, langs: [] };
                  if (nent.subdir) {
                    const langDir = await parseDir(nent.target);
                    if (langDir) {
                      for (const langEnt of langDir.entries) {
                        if (!langEnt.subdir) {
                          const dataEntryRel = langEnt.target;
                          const deo = base + dataEntryRel;
                          if (isInside(deo + 16)) {
                            const dv = await view(deo, 16);
                            const DataRVA = u32(dv, 0);
                            const Size = u32(dv, 4);
                            const CodePage = u32(dv, 8);
                            const Reserved = u32(dv, 12);
                            const lang = langEnt.id != null ? langEnt.id : null;
                            const langEntry = { lang, size: Size, codePage: CodePage, dataRVA: DataRVA, reserved: Reserved };
                            // Previews for common resource types
                            try {
                              const dataOff = rvaToOff(DataRVA);
                              if (typeName === "ICON" && dataOff != null && Size > 0 && Size <= 262144) {
                                const data = new Uint8Array(await file.slice(dataOff, dataOff + Size).arrayBuffer());
                                // PNG-backed icon
                                if (data.length >= 8 && data[0] === 0x89 && data[1] === 0x50 && data[2] === 0x4e && data[3] === 0x47 && data[4] === 0x0d && data[5] === 0x0a && data[6] === 0x1a && data[7] === 0x0a) {
                                  langEntry.previewKind = "image";
                                  langEntry.previewMime = "image/png";
                                  langEntry.previewDataUrl = `data:image/png;base64,${base64FromU8(data)}`;
                                } else if (data.length >= 40) {
                                  // DIB-backed icon (BITMAPINFOHEADER or variants)
                                  const dvb = new DataView(data.buffer, data.byteOffset, Math.min(64, data.length));
                                  const hdrSize = dvb.getUint32(0, true);
                                  if (hdrSize === 40 || hdrSize === 108 || hdrSize === 124) {
                                    const w = dvb.getInt32(4, true);
                                    const h2 = dvb.getInt32(8, true);
                                    const planes = 1;
                                    const bitCount = dvb.getUint16(14, true);
                                    const outW = Math.max(1, Math.min(256, Math.abs(w)));
                                    const outH = Math.max(1, Math.min(256, Math.abs(Math.floor(h2 / 2))));
                                    const dirSize = 6 + 16;
                                    const ico = new Uint8Array(dirSize + data.length);
                                    const dvi = new DataView(ico.buffer);
                                    dvi.setUint16(0, 0, true); // reserved
                                    dvi.setUint16(2, 1, true); // type icon
                                    dvi.setUint16(4, 1, true); // count
                                    dvi.setUint8(6, outW === 256 ? 0 : outW);
                                    dvi.setUint8(7, outH === 256 ? 0 : outH);
                                    dvi.setUint8(8, 0);
                                    dvi.setUint8(9, 0);
                                    dvi.setUint16(10, planes, true);
                                    dvi.setUint16(12, bitCount, true);
                                    dvi.setUint32(14, data.length >>> 0, true);
                                    dvi.setUint32(18, dirSize >>> 0, true);
                                    ico.set(data, dirSize);
                                    langEntry.previewKind = "image";
                                    langEntry.previewMime = "image/x-icon";
                                    langEntry.previewDataUrl = `data:image/x-icon;base64,${base64FromU8(ico)}`;
                                  }
                                }
                              } else if (typeName === "MANIFEST" && dataOff != null && Size > 0) {
                                const data = new Uint8Array(await file.slice(dataOff, dataOff + Math.min(Size, 16 * 1024)).arrayBuffer());
                                let text = "";
                                if (data.length >= 2 && data[0] === 0xff && data[1] === 0xfe) {
                                  for (let i = 2; i + 1 < data.length; i += 2) {
                                    const ch = data[i] | (data[i + 1] << 8);
                                    text += String.fromCharCode(ch);
                                  }
                                } else {
                                  try { text = new TextDecoder("utf-8").decode(data); } catch {}
                                }
                                if (text) {
                                  langEntry.previewKind = "text";
                                  langEntry.textPreview = text;
                                }
                              } else if (typeName === "VERSION" && dataOff != null && Size >= 0x40 && Size <= 64 * 1024) {
                                const buf = new Uint8Array(await file.slice(dataOff, dataOff + Size).arrayBuffer());
                                const dvv = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
                                const readUtf16z = offset => {
                                  let result = "";
                                  for (let pos = offset; pos + 1 < buf.length; pos += 2) {
                                    const ch = dvv.getUint16(pos, true);
                                    if (ch === 0) break;
                                    result += String.fromCharCode(ch);
                                  }
                                  return result;
                                };
                                const length = dvv.getUint16(0, true);
                                const valueLength = dvv.getUint16(2, true);
                                const type = dvv.getUint16(4, true);
                                const key = readUtf16z(6);
                                const valueStart = (6 + key.length * 2 + 2 + 3) & ~3;
                                let fixed = null;
                                if (key === "VS_VERSION_INFO" && valueLength >= 52 && valueStart + 52 <= buf.length) {
                                  const v0 = dvv.getUint32(valueStart + 0, true);
                                  const v1 = dvv.getUint32(valueStart + 4, true);
                                  const v2 = dvv.getUint32(valueStart + 8, true);
                                  const v3 = dvv.getUint32(valueStart + 12, true);
                                  const parsePair = v => ({
                                    major: (v >>> 16) & 0xffff,
                                    minor: v & 0xffff
                                  });
                                  const fileVer = { high: parsePair(v0), low: parsePair(v1) };
                                  const prodVer = { high: parsePair(v2), low: parsePair(v3) };
                                  fixed = {
                                    fileVersion: fileVer,
                                    productVersion: prodVer,
                                    fileVersionString: `${fileVer.high.major}.${fileVer.high.minor}.${fileVer.low.major}.${fileVer.low.minor}`,
                                    productVersionString: `${prodVer.high.major}.${prodVer.high.minor}.${prodVer.low.major}.${prodVer.low.minor}`
                                  };
                                }
                                langEntry.previewKind = "version";
                                langEntry.versionInfo = {
                                  length,
                                  valueLength,
                                  type,
                                  key,
                                  fixed
                                };
                              } else if (typeName === "GROUP_ICON") {
                                const grpOff = rvaToOff(DataRVA);
                                if (grpOff != null && Size >= 6) {
                                  const ab = await file.slice(grpOff, grpOff + Math.min(Size, 4096)).arrayBuffer();
                                  const g = new DataView(ab);
                                  const idCount = g.getUint16(4, true);
                                  if (idCount > 0 && 6 + idCount * 14 <= g.byteLength) {
                                    let pick = 0; let bestW = 0;
                                    for (let j = 0; j < idCount; j++) {
                                      const w = g.getUint8(6 + j * 14 + 0) || 256;
                                      if (w === 32) { pick = j; bestW = w; break; }
                                      if (w > bestW) { pick = j; bestW = w; }
                                    }
                                    const eOff2 = 6 + pick * 14;
                                    const bWidth = g.getUint8(eOff2 + 0) || 256;
                                    const bHeight = g.getUint8(eOff2 + 1) || 256;
                                    const bColorCount = g.getUint8(eOff2 + 2);
                                    const wPlanes = g.getUint16(eOff2 + 4, true);
                                    const wBitCount = g.getUint16(eOff2 + 6, true);
                                    const nID = g.getUint16(eOff2 + 12, true);
                                    const ic = iconIndex.get(nID);
                                    if (ic) {
                                      const imgOff = rvaToOff(ic.rva);
                                      if (imgOff != null && ic.size > 0 && ic.size <= 2000000) {
                                        const imageData = new Uint8Array(await file.slice(imgOff, imgOff + ic.size).arrayBuffer());
                                        const dirSize = 6 + 16;
                                        const ico = new Uint8Array(dirSize + imageData.length);
                                        const dv3 = new DataView(ico.buffer);
                                        dv3.setUint16(0, 0, true);
                                        dv3.setUint16(2, 1, true);
                                        dv3.setUint16(4, 1, true);
                                        dv3.setUint8(6, bWidth === 256 ? 0 : bWidth);
                                        dv3.setUint8(7, bHeight === 256 ? 0 : bHeight);
                                        dv3.setUint8(8, bColorCount);
                                        dv3.setUint8(9, 0);
                                        dv3.setUint16(10, wPlanes, true);
                                        dv3.setUint16(12, wBitCount, true);
                                        dv3.setUint32(14, imageData.length >>> 0, true);
                                        dv3.setUint32(18, dirSize >>> 0, true);
                                        ico.set(imageData, dirSize);
                                        langEntry.previewKind = "image";
                                        langEntry.previewMime = "image/x-icon";
                                        langEntry.previewDataUrl = `data:image/x-icon;base64,${base64FromU8(ico)}`;
                                      }
                                    }
                                  }
                                }
                              }
                            } catch {}
                            child.langs.push(langEntry);
                          }
                        }
                      }
                    }
                  }
                  entries.push(child);
                }
                detail.push({ typeName, entries });
              }
            }
          }
          resources = { top, detail };
        }
      }
    }
  }

  // Exception directory (.pdata) summary (x64)
  let exception = null; {
    const ed = dataDirs.find(d => d.name === "EXCEPTION");
    if (ed?.rva && ed.size >= 12) {
      const start = rvaToOff(ed.rva);
      if (start != null) {
        addCov("EXCEPTION (.pdata)", start, ed.size);
        const count = Math.floor(ed.size / 12);
        const sample = [];
        const view = new DataView(await file.slice(start, start + Math.min(ed.size, 12 * 64)).arrayBuffer());
        const n = Math.min(count, 64);
        for (let i = 0; i < n; i++) {
          const b = i * 12;
          const BeginAddress = view.getUint32(b + 0, true);
          const EndAddress = view.getUint32(b + 4, true);
          const UnwindInfoAddress = view.getUint32(b + 8, true);
          sample.push({ BeginAddress, EndAddress, UnwindInfoAddress });
        }
        exception = { count, sample };
      }
    }
  }

  // Bound imports summary
  let boundImports = null; {
    const bd = dataDirs.find(d => d.name === "BOUND_IMPORT");
    if (bd?.rva && bd.size >= 8) {
      const base = rvaToOff(bd.rva);
      if (base != null) {
        addCov("BOUND_IMPORT", base, bd.size);
        const end = base + bd.size;
        const entries = [];
        let off = base;
        while (off + 8 <= end) {
          const dv = new DataView(await file.slice(off, off + 8).arrayBuffer());
          const TimeDateStamp = dv.getUint32(0, true);
          const OffsetModuleName = dv.getUint16(4, true);
          const NumberOfModuleForwarderRefs = dv.getUint16(6, true);
          if (TimeDateStamp === 0 && OffsetModuleName === 0 && NumberOfModuleForwarderRefs === 0) break;
          let name = "";
          const nameOff = base + OffsetModuleName;
          if (nameOff >= base && nameOff < end) {
            const nameView = new DataView(await file.slice(nameOff, nameOff + 256).arrayBuffer());
            name = readAsciiString(nameView, 0, 256);
          }
          entries.push({ name, TimeDateStamp, NumberOfModuleForwarderRefs });
          off += 8;
        }
        boundImports = { entries };
      }
    }
  }

  // Delay-load imports summary
  let delayImports = null; {
    const dd = dataDirs.find(d => d.name === "DELAY_IMPORT");
    if (dd?.rva && dd.size >= 32) {
      const base = rvaToOff(dd.rva);
      if (base != null) {
        addCov("DELAY_IMPORT", base, dd.size);
        const entries = [];
        const end = base + dd.size;
        let off = base;
        // IMAGE_DELAYLOAD_DESCRIPTOR is 32 bytes (32-bit) / 48 bytes (with VA); parse minimal 32 bytes to find DllNameRVA
        while (off + 32 <= end) {
          const dv = new DataView(await file.slice(off, off + 32).arrayBuffer());
          const Attributes = dv.getUint32(0, true);
          const DllNameRVA = dv.getUint32(4, true);
          const ModuleHandleRVA = dv.getUint32(8, true);
          const ImportAddressTableRVA = dv.getUint32(12, true);
          const ImportNameTableRVA = dv.getUint32(16, true);
          const BoundImportAddressTableRVA = dv.getUint32(20, true);
          const UnloadInformationTableRVA = dv.getUint32(24, true);
          const TimeDateStamp = dv.getUint32(28, true);
          if (Attributes === 0 && DllNameRVA === 0) break;
          let name = "";
          {
            const nOff = rvaToOff(DllNameRVA);
            if (nOff != null) {
              const nameView = new DataView(await file.slice(nOff, nOff + 256).arrayBuffer());
              name = readAsciiString(nameView, 0, 256);
            }
          }
          // Convert possible VA to RVA depending on Attributes bit 0
          const rvaFromMaybeVa = (val) => {
            const isRva = (Attributes & 1) !== 0;
            let r = isRva ? (val >>> 0) : (((val >>> 0) - (ImageBase >>> 0)) >>> 0);
            return r >>> 0;
          };
          // Parse thunk names from ImportNameTable
          const funcs = [];
          const intRva = rvaFromMaybeVa(ImportNameTableRVA);
          const intOff = intRva ? rvaToOff(intRva) : null;
          if (intOff != null) {
            if (isPlus) {
              for (let t = 0; t < 8 * 16384; t += 8) {
                const dv2 = new DataView(await file.slice(intOff + t, intOff + t + 8).arrayBuffer());
                const val = dv2.getBigUint64(0, true);
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
              for (let t = 0; t < 4 * 32768; t += 4) {
                const dv2 = new DataView(await file.slice(intOff + t, intOff + t + 4).arrayBuffer());
                const val = dv2.getUint32(0, true);
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
          entries.push({ name, Attributes, ModuleHandleRVA, ImportAddressTableRVA, ImportNameTableRVA, BoundImportAddressTableRVA, UnloadInformationTableRVA, TimeDateStamp, functions: funcs });
          off += 32;
        }
        delayImports = { entries };
      }
    }
  }

  // CLR header (managed)
  let clr = null; {
    const cd = dataDirs.find(d => d.name === "CLR_RUNTIME");
    if (cd?.rva && cd.size >= 0x48) {
      const off = rvaToOff(cd.rva);
      if (off != null) {
        addCov("CLR (.NET) header", off, cd.size);
        const dv = new DataView(await file.slice(off, off + Math.min(cd.size, 0x48)).arrayBuffer());
        const cb = dv.getUint32(0, true);
        const MajorRuntimeVersion = dv.getUint16(4, true), MinorRuntimeVersion = dv.getUint16(6, true);
        const MetaDataRVA = dv.getUint32(8, true), MetaDataSize = dv.getUint32(12, true);
        const Flags = dv.getUint32(16, true);
        const EntryPointToken = dv.getUint32(20, true);
        clr = { cb, MajorRuntimeVersion, MinorRuntimeVersion, MetaDataRVA, MetaDataSize, Flags, EntryPointToken };
        const mdOff = rvaToOff(MetaDataRVA);
        if (mdOff != null && MetaDataSize >= 0x20) {
          try {
            const mdHead = new DataView(await file.slice(mdOff, mdOff + Math.min(MetaDataSize, 0x4000)).arrayBuffer());
            let p = 0;
            const sig = mdHead.getUint32(p, true); p += 4; // 'BSJB' (0x424A5342)
            const verMajor = mdHead.getUint16(p, true); p += 2;
            const verMinor = mdHead.getUint16(p, true); p += 2;
            const reserved = mdHead.getUint32(p, true); p += 4;
            const verLen = mdHead.getUint32(p, true); p += 4;
            let verStr = "";
            if (verLen > 0 && p + verLen <= mdHead.byteLength) {
              const bytes = new Uint8Array(mdHead.buffer, mdHead.byteOffset + p, verLen);
              verStr = String.fromCharCode(...bytes.filter(b => b >= 0x20 && b <= 0x7e));
              p += verLen;
              p = (p + 3) & ~3; // align
            }
            const flags = mdHead.getUint16(p, true); p += 2;
            const streamCount = mdHead.getUint16(p, true); p += 2;
            const streams = [];
            for (let i = 0; i < streamCount && p + 8 <= mdHead.byteLength; i++) {
              const offset = mdHead.getUint32(p, true); p += 4;
              const size = mdHead.getUint32(p, true); p += 4;
              let name = "";
              let limit = Math.min(mdHead.byteLength - p, 64);
              for (let j = 0; j < limit; j++) { const c = mdHead.getUint8(p++); if (c === 0) break; name += String.fromCharCode(c); }
              p = (p + 3) & ~3;
              streams.push({ name, offset, size });
            }
            clr.meta = { version: verStr.trim(), verMajor, verMinor, streams };
          } catch {}
        }
      }
    }
  }

  // Security directory (WIN_CERTIFICATE)
  let security = null; {
    const sd = dataDirs.find(d => d.name === "SECURITY");
    if (sd?.rva && sd.size >= 8) {
      const off = sd.rva; // NOTE: file offset, not RVA
      if (off + 8 <= file.size) {
        addCov("SECURITY (WIN_CERTIFICATE)", off, sd.size);
        const end = Math.min(file.size, off + sd.size);
        let pos = off; let count = 0; const certs = [];
        while (pos + 8 <= end && count < 8) {
          const dv = new DataView(await file.slice(pos, pos + 8).arrayBuffer());
          const Length = dv.getUint32(0, true);
          const Revision = dv.getUint16(4, true);
          const CertificateType = dv.getUint16(6, true);
          if (Length < 8) break;
          certs.push({ Length, Revision, CertificateType });
          pos += ((Length + 7) & ~7); // 8-byte aligned
          count++;
        }
        security = { count, certs };
      }
    }
  }

  // IAT summary
  let iat = null; {
    const id = dataDirs.find(d => d.name === "IAT");
    if (id?.rva && id.size) {
      const off = rvaToOff(id.rva);
      if (off != null) { addCov("IAT", off, id.size); iat = { rva: id.rva, size: id.size }; }
    }
  }

  return {
    dos,
    signature: "PE",
    coff,
    opt,
    dirs: dataDirs,
    sections,
    entrySection,
    rvaToOff,
    imports,
    rsds,
    loadcfg,
    exports,
    tls,
    reloc,
    exception,
    boundImports,
    delayImports,
    clr,
    security,
    iat,
    resources,
    overlaySize,
    imageEnd,
    imageSizeMismatch,
    coverage,
    hasCert: !!(dataDirs.find(d => d.name === "SECURITY")?.size)
  };
}
