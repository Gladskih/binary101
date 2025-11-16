"use strict";

const knownResourceType = id => ({
  1: "CURSOR", 2: "BITMAP", 3: "ICON", 4: "MENU", 5: "DIALOG", 6: "STRING", 7: "FONTDIR", 8: "FONT", 9: "ACCELERATOR",
  10: "RCDATA", 11: "MESSAGETABLE", 12: "GROUP_CURSOR", 14: "GROUP_ICON", 16: "VERSION", 17: "DLGINCLUDE", 19: "PLUGPLAY",
  20: "VXD", 21: "ANICURSOR", 22: "ANIICON", 23: "HTML", 24: "MANIFEST"
})[id] || null;

export async function buildResourceTree(file, dataDirs, rvaToOff, addCoverageRegion) {
  const dir = dataDirs.find(d => d.name === "RESOURCE");
  if (!dir?.rva || dir.size < 16) return null;
  const base = rvaToOff(dir.rva);
  if (base == null) return null;
  addCoverageRegion("RESOURCE directory", base, dir.size);
  const limitEnd = base + dir.size;
  const view = async (off, len) => new DataView(await file.slice(off, off + len).arrayBuffer());
  const u16 = (dv, off) => dv.getUint16(off, true);
  const u32 = (dv, off) => dv.getUint32(off, true);
  const isInside = off => off >= base && off < limitEnd;

  const parseDir = async rel => {
    const off = base + rel;
    if (!isInside(off + 16)) return null;
    const dv = await view(off, 16);
    const Named = u16(dv, 12);
    const Ids = u16(dv, 14);
    const count = Named + Ids;
    const entries = [];
    for (let index = 0; index < count; index++) {
      const e = await view(off + 16 + index * 8, 8);
      const Name = u32(e, 0);
      const OffsetToData = u32(e, 4);
      const nameIsString = (Name & 0x80000000) !== 0;
      const subdir = (OffsetToData & 0x80000000) !== 0;
      entries.push({
        nameIsString,
        subdir,
        nameOrId: nameIsString ? (Name & 0x7fffffff) : (Name & 0xffff),
        target: OffsetToData & 0x7fffffff
      });
    }
    return { Named, Ids, entries };
  };

  const readUcs2Label = async rel => {
    const so = base + rel;
    if (so + 2 > limitEnd) return "";
    const dv = await view(so, 2);
    const len = u16(dv, 0);
    const bytes = new Uint8Array(await file.slice(so + 2, Math.min(limitEnd, so + 2 + len * 2)).arrayBuffer());
    let s = "";
    for (let index = 0; index + 1 < bytes.length; index += 2) {
      const ch = bytes[index] | (bytes[index + 1] << 8);
      if (ch === 0) break;
      s += String.fromCharCode(ch);
    }
    return s;
  };

  const root = await parseDir(0);
  if (!root) return null;

  const top = [];
  const detail = [];

  for (const typeEntry of root.entries) {
    let typeName = "(named)";
    if (!typeEntry.nameIsString && typeEntry.nameOrId != null) {
      typeName = knownResourceType(typeEntry.nameOrId) || `TYPE_${typeEntry.nameOrId}`;
    } else if (typeEntry.nameIsString) {
      typeName = await readUcs2Label(typeEntry.nameOrId);
    }

    let leafCount = 0;
    const typeDetailEntries = [];

    if (typeEntry.subdir) {
      const nameDir = await parseDir(typeEntry.target);
      if (nameDir) {
        for (const nameEntry of nameDir.entries) {
          const child = { id: nameEntry.nameIsString ? null : nameEntry.nameOrId ?? null, name: null, langs: [] };
          if (nameEntry.nameIsString && nameEntry.nameOrId != null) {
            child.name = await readUcs2Label(nameEntry.nameOrId);
          }
          if (nameEntry.subdir) {
            const langDir = await parseDir(nameEntry.target);
            if (langDir) {
              for (const langEnt of langDir.entries) {
                if (langEnt.subdir) continue;
                const dataEntryOff = base + langEnt.target;
                if (!isInside(dataEntryOff + 16)) continue;
                const dv = await view(dataEntryOff, 16);
                const DataRVA = u32(dv, 0);
                const Size = u32(dv, 4);
                const CodePage = u32(dv, 8);
                const Reserved = u32(dv, 12);
                const lang = langEnt.nameIsString ? null : (langEnt.nameOrId ?? null);
                const langEntry = { lang, size: Size, codePage: CodePage, dataRVA: DataRVA, reserved: Reserved };
                child.langs.push(langEntry);
                leafCount++;
              }
            }
          }
          if (child.langs.length) typeDetailEntries.push(child);
        }
      }
    }

    top.push({ typeName, kind: typeEntry.nameIsString ? "name" : "id", leafCount });
    if (typeDetailEntries.length) detail.push({ typeName, entries: typeDetailEntries });
  }

  return { base, limitEnd, top, detail, view, rvaToOff };
}

