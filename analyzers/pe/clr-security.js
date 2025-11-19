"use strict";

export async function parseClrDirectory(file, dataDirs, rvaToOff, addCoverageRegion) {
  const dir = dataDirs.find(d => d.name === "CLR_RUNTIME");
  if (!dir?.rva || dir.size < 0x48) return null;
  const base = rvaToOff(dir.rva);
  if (base == null) return null;
  addCoverageRegion("CLR (.NET) header", base, dir.size);
  const view = new DataView(await file.slice(base, base + Math.min(dir.size, 0x48)).arrayBuffer());
  const cb = view.getUint32(0, true);
  const MajorRuntimeVersion = view.getUint16(4, true);
  const MinorRuntimeVersion = view.getUint16(6, true);
  const MetaDataRVA = view.getUint32(8, true);
  const MetaDataSize = view.getUint32(12, true);
  const Flags = view.getUint32(16, true);
  const EntryPointToken = view.getUint32(20, true);
  const metaOffset = rvaToOff(MetaDataRVA);
  const clr = { cb, MajorRuntimeVersion, MinorRuntimeVersion, MetaDataRVA, MetaDataSize, Flags, EntryPointToken };
  if (metaOffset != null && MetaDataSize >= 0x20) {
    try {
      const md = new DataView(await file.slice(metaOffset, metaOffset + Math.min(MetaDataSize, 0x4000)).arrayBuffer());
      let p = 0;
      const sig = md.getUint32(p, true); p += 4;
      const verMajor = md.getUint16(p, true); p += 2;
      const verMinor = md.getUint16(p, true); p += 2;
      const reserved = md.getUint32(p, true); p += 4;
      const verLen = md.getUint32(p, true); p += 4;
      let verStr = "";
      if (verLen > 0 && p + verLen <= md.byteLength) {
        const bytes = new Uint8Array(md.buffer, md.byteOffset + p, verLen);
        verStr = String.fromCharCode(...bytes.filter(b => b >= 0x20 && b <= 0x7e)).trim();
        p = (p + verLen + 3) & ~3;
      }
      const flags = md.getUint16(p, true); p += 2;
      const streamCount = md.getUint16(p, true); p += 2;
      const streams = [];
      for (let i = 0; i < streamCount && p + 8 <= md.byteLength; i++) {
        const offset = md.getUint32(p, true); p += 4;
        const size = md.getUint32(p, true); p += 4;
        let name = "";
        const limit = Math.min(md.byteLength - p, 64);
        for (let j = 0; j < limit; j++) {
          const c = md.getUint8(p++);
          if (c === 0) break;
          name += String.fromCharCode(c);
        }
        p = (p + 3) & ~3;
        streams.push({ name, offset, size });
      }
      clr.meta = { version: verStr, verMajor, verMinor, streams, sig, flags, reserved };
    } catch {
      // malformed CLR metadata; keep only header fields
    }
  }
  return clr;
}

export async function parseSecurityDirectory(file, dataDirs, addCoverageRegion) {
  const dir = dataDirs.find(d => d.name === "SECURITY");
  if (!dir?.rva || dir.size < 8) return null;
  const off = dir.rva;
  if (off + 8 > file.size) return null;
  addCoverageRegion("SECURITY (WIN_CERTIFICATE)", off, dir.size);
  const end = Math.min(file.size, off + dir.size);
  let pos = off;
  let count = 0;
  const certs = [];
  while (pos + 8 <= end && count < 8) {
    const dv = new DataView(await file.slice(pos, pos + 8).arrayBuffer());
    const Length = dv.getUint32(0, true);
    const Revision = dv.getUint16(4, true);
    const CertificateType = dv.getUint16(6, true);
    if (Length < 8) break;
    certs.push({ Length, Revision, CertificateType });
    pos += (Length + 7) & ~7;
    count++;
  }
  return { count, certs };
}

