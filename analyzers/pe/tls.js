"use strict";

export async function parseTlsDirectory(file, dataDirs, rvaToOff, addCoverageRegion, isPlus, imageBase) {
  const dir = dataDirs.find(d => d.name === "TLS");
  if (!dir?.rva) return null;
  const base = rvaToOff(dir.rva);
  if (base == null) return null;
  const size = dir.size || (isPlus ? 0x30 : 0x18);
  addCoverageRegion("TLS directory", base, Math.min(size, isPlus ? 0x30 : 0x18));
  if (isPlus) {
    const dv = new DataView(await file.slice(base, base + 0x30).arrayBuffer());
    const StartAddressOfRawData = Number(dv.getBigUint64(0, true));
    const EndAddressOfRawData = Number(dv.getBigUint64(8, true));
    const AddressOfIndex = Number(dv.getBigUint64(16, true));
    const AddressOfCallBacks = Number(dv.getBigUint64(24, true));
    const SizeOfZeroFill = dv.getUint32(32, true);
    const Characteristics = dv.getUint32(36, true);
    let CallbackCount = 0;
    if (AddressOfCallBacks) {
      const rva = (AddressOfCallBacks - imageBase) >>> 0;
      const po = rvaToOff(rva);
      if (po != null) {
        for (let index = 0; index < 1024; index++) {
          const ptr = new DataView(
            await file.slice(po + index * 8, po + index * 8 + 8).arrayBuffer()
          ).getBigUint64(0, true);
          if (ptr === 0n) {
            CallbackCount = index;
            break;
          }
        }
      }
    }
    return {
      StartAddressOfRawData,
      EndAddressOfRawData,
      AddressOfIndex,
      AddressOfCallBacks,
      SizeOfZeroFill,
      Characteristics,
      CallbackCount
    };
  }
  const dv = new DataView(await file.slice(base, base + 0x18).arrayBuffer());
  const StartAddressOfRawData = dv.getUint32(0, true);
  const EndAddressOfRawData = dv.getUint32(4, true);
  const AddressOfIndex = dv.getUint32(8, true);
  const AddressOfCallBacks = dv.getUint32(12, true);
  const SizeOfZeroFill = dv.getUint32(16, true);
  const Characteristics = dv.getUint32(20, true);
  return {
    StartAddressOfRawData,
    EndAddressOfRawData,
    AddressOfIndex,
    AddressOfCallBacks,
    SizeOfZeroFill,
    Characteristics,
    CallbackCount: 0
  };
}

