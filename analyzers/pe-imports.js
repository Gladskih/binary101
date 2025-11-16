"use strict";

import { readAsciiString } from "../binary-utils.js";

export async function parseImportDirectory(file, dataDirs, rvaToOff, addCoverageRegion, isPlus) {
  const impDir = dataDirs.find(d => d.name === "IMPORT");
  const imports = [];
  if (!impDir?.rva) return imports;
  const start = rvaToOff(impDir.rva);
  if (start == null) return imports;
  addCoverageRegion("IMPORT directory", start, impDir.size);
  const maxDescriptors = Math.max(1, Math.floor(impDir.size / 20));
  for (let index = 0; index < maxDescriptors; index++) {
    const offset = start + index * 20;
    const desc = new DataView(await file.slice(offset, offset + 20).arrayBuffer());
    const originalFirstThunk = desc.getUint32(0, true);
    const nameRva = desc.getUint32(12, true);
    const firstThunk = desc.getUint32(16, true);
    if (!originalFirstThunk && !nameRva && !firstThunk) break;
    const nameOffset = rvaToOff(nameRva);
    let dllName = "";
    if (nameOffset != null) {
      const dv = new DataView(await file.slice(nameOffset, nameOffset + 256).arrayBuffer());
      dllName = readAsciiString(dv, 0, 256);
    }
    const thunkRva = originalFirstThunk || firstThunk;
    const thunkOffset = rvaToOff(thunkRva);
    const functions = [];
    if (thunkOffset != null) {
      if (isPlus) {
        for (let t = 0; t < 8 * 16384; t += 8) {
          const dv = new DataView(await file.slice(thunkOffset + t, thunkOffset + t + 8).arrayBuffer());
          const value = dv.getBigUint64(0, true);
          if (value === 0n) break;
          if ((value & 0x8000000000000000n) !== 0n) {
            functions.push({ ordinal: Number(value & 0xffffn) });
          } else {
            const hintNameRva = Number(value & 0xffffffffn);
            const hintNameOffset = rvaToOff(hintNameRva);
            if (hintNameOffset != null) {
              const hintView = new DataView(await file.slice(hintNameOffset, hintNameOffset + 2).arrayBuffer());
              const hint = hintView.getUint16(0, true);
              let name = "";
              let pos = hintNameOffset + 2;
              for (;;) {
                const chunk = new Uint8Array(await file.slice(pos, pos + 64).arrayBuffer());
                const zeroIndex = chunk.indexOf(0);
                if (zeroIndex === -1) {
                  name += String.fromCharCode(...chunk);
                  pos += 64;
                  if (pos > file.size) break;
                } else {
                  if (zeroIndex > 0) name += String.fromCharCode(...chunk.slice(0, zeroIndex));
                  break;
                }
              }
              functions.push({ hint, name });
            } else {
              functions.push({ name: "<bad RVA>" });
            }
          }
        }
      } else {
        for (let t = 0; t < 4 * 32768; t += 4) {
          const dv = new DataView(await file.slice(thunkOffset + t, thunkOffset + t + 4).arrayBuffer());
          const value = dv.getUint32(0, true);
          if (value === 0) break;
          if ((value & 0x80000000) !== 0) {
            functions.push({ ordinal: value & 0xffff });
          } else {
            const hintNameOffset = rvaToOff(value);
            if (hintNameOffset != null) {
              const hintView = new DataView(await file.slice(hintNameOffset, hintNameOffset + 2).arrayBuffer());
              const hint = hintView.getUint16(0, true);
              let name = "";
              let pos = hintNameOffset + 2;
              for (;;) {
                const chunk = new Uint8Array(await file.slice(pos, pos + 64).arrayBuffer());
                const zeroIndex = chunk.indexOf(0);
                if (zeroIndex === -1) {
                  name += String.fromCharCode(...chunk);
                  pos += 64;
                  if (pos > file.size) break;
                } else {
                  if (zeroIndex > 0) name += String.fromCharCode(...chunk.slice(0, zeroIndex));
                  break;
                }
              }
              functions.push({ hint, name });
            } else {
              functions.push({ name: "<bad RVA>" });
            }
          }
        }
      }
    }
    imports.push({ dll: dllName, functions });
  }
  return imports;
}

