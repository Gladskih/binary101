"use strict";

import { readAsciiString } from "../../binary-utils.js";

export async function parseExportDirectory(file, dataDirs, rvaToOff, addCoverageRegion) {
  const dir = dataDirs.find(d => d.name === "EXPORT");
  if (!dir?.rva || dir.size < 40) return null;
  const base = rvaToOff(dir.rva);
  if (base == null) return null;
  addCoverageRegion("EXPORT directory", base, dir.size);
  const dv = new DataView(await file.slice(base, base + Math.min(dir.size, 0x200)).arrayBuffer());
  const Characteristics = dv.getUint32(0, true);
  const TimeDateStamp = dv.getUint32(4, true);
  const MajorVersion = dv.getUint16(8, true);
  const MinorVersion = dv.getUint16(10, true);
  const NameRVA = dv.getUint32(12, true);
  const Base = dv.getUint32(16, true);
  const NumberOfFunctions = dv.getUint32(20, true);
  const NumberOfNames = dv.getUint32(24, true);
  const AddressOfFunctions = dv.getUint32(28, true);
  const AddressOfNames = dv.getUint32(32, true);
  const AddressOfNameOrdinals = dv.getUint32(36, true);

  let dllName = "";
  const nameOffset = rvaToOff(NameRVA);
  if (nameOffset != null) {
    const nameView = new DataView(await file.slice(nameOffset, nameOffset + 256).arrayBuffer());
    dllName = readAsciiString(nameView, 0, 256);
  }

  const entries = [];
  const eatOffset = rvaToOff(AddressOfFunctions);
  const namesOffset = rvaToOff(AddressOfNames);
  const ordinalsOffset = rvaToOff(AddressOfNameOrdinals);

  if (eatOffset != null && NumberOfFunctions) {
    const eat = new DataView(await file.slice(eatOffset, eatOffset + NumberOfFunctions * 4).arrayBuffer());
    let nameTable = null;
    let ordinalTable = null;
    if (namesOffset != null && ordinalsOffset != null && NumberOfNames) {
      nameTable = new DataView(await file.slice(namesOffset, namesOffset + NumberOfNames * 4).arrayBuffer());
      ordinalTable = new DataView(await file.slice(ordinalsOffset, ordinalsOffset + NumberOfNames * 2).arrayBuffer());
    }
    const nameMap = new Map();
    if (nameTable && ordinalTable) {
      for (let index = 0; index < NumberOfNames; index++) {
        const rva = nameTable.getUint32(index * 4, true);
        const ord = ordinalTable.getUint16(index * 2, true);
        const so = rvaToOff(rva);
        let name = "";
        if (so != null) {
          const nameView = new DataView(await file.slice(so, so + 256).arrayBuffer());
          name = readAsciiString(nameView, 0, 256);
        }
        nameMap.set(ord, name);
      }
    }

    for (let ord = 0; ord < NumberOfFunctions; ord++) {
      const rva = eat.getUint32(ord * 4, true);
      const isForwarder = rva >= dir.rva && rva < (dir.rva + dir.size);
      let forwarder = null;
      if (isForwarder) {
        const fOff = rvaToOff(rva);
        if (fOff != null) {
          const forwardView = new DataView(await file.slice(fOff, fOff + 256).arrayBuffer());
          forwarder = readAsciiString(forwardView, 0, 256);
        }
      }
      entries.push({
        ordinal: Base + ord,
        name: nameMap.get(ord) || null,
        rva,
        forwarder
      });
    }
  }

  return {
    dllName,
    Characteristics,
    TimeDateStamp,
    MajorVersion,
    MinorVersion,
    Base,
    NumberOfFunctions,
    NumberOfNames,
    AddressOfFunctions,
    AddressOfNames,
    AddressOfNameOrdinals,
    entries
  };
}
