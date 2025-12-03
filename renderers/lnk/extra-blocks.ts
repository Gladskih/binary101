"use strict";

import { safe } from "../../html-utils.js";
import { toHex32 } from "../../binary-utils.js";
import type {
  LnkExtraDataBlock,
  LnkProperty,
  LnkPropertyStorage,
  LnkPropertyStoreData,
  LnkTrackerData,
  LnkVistaIdListData
} from "../../analyzers/lnk/types.js";

const formatPropertyValue = (value: unknown): string => {
  if (value === null || value === undefined) return "-";
  if (Array.isArray(value)) return value.map(v => formatPropertyValue(v)).join(", ");
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "bigint") return value.toString();
  return String(value);
};

const renderPropertyStore = (parsed: LnkPropertyStoreData | null | undefined): string => {
  const storages = parsed?.storages || [];
  if (!storages.length) return `<div class="smallNote">Property store present but empty.</div>`;
  const out: string[] = [];
  storages.forEach((storage: LnkPropertyStorage) => {
    const header = storage.formatId ? `FMTID ${safe(storage.formatId)}` : "Property storage";
    const suffix = storage.truncated ? " (truncated)" : "";
    const magic = storage.magic ? ` ${safe(storage.magic)}` : "";
    out.push(`<div class="smallNote">${header}${magic}${suffix}</div>`);
    if (storage.properties?.length) {
      out.push(`<ul class="smallNote">`);
      storage.properties.forEach((prop: LnkProperty) => {
        const name = prop.name || `Property ${prop.id}`;
        let typeLabel = "";
        if (prop.type != null) {
          const baseHex = toHex32(prop.type & 0xffff, 4);
          const vtName = prop.typeName ? `VT_${prop.typeName}` : `VT_0x${baseHex}`;
          typeLabel = ` (${safe(vtName)} 0x${baseHex})`;
        }
        const value = formatPropertyValue(prop.value);
        const truncated = prop.truncated ? " [truncated]" : "";
        out.push(
          `<li title="FMTID ${safe(storage.formatId || "")}, PID ${prop.id}">${safe(name)}${typeLabel}: ${safe(
            value
          )}${truncated}</li>`
        );
      });
      out.push(`</ul>`);
    }
  });
  return out.join("");
};

const describeBlock = (block: LnkExtraDataBlock): string => {
  const signature = block.signature >>> 0;
  switch (signature) {
    case 0xa0000001:
    case 0xa0000006:
    case 0xa0000007: {
      const parsed = block.parsed as { ansi: string | null; unicode: string | null } | null;
      if (!parsed) return "";
      const ansi = parsed.ansi ? safe(parsed.ansi) : "-";
      const unicode = parsed.unicode ? safe(parsed.unicode) : "-";
      return `<div class="smallNote">ANSI: ${ansi}<br/>Unicode: ${unicode}</div>`;
    }
    case 0xa0000003: {
      const parsed = block.parsed as LnkTrackerData | null;
      if (!parsed) return "";
      const machine = parsed.machineId ? `Machine: ${safe(parsed.machineId)}<br/>` : "";
      const droidVolume = parsed.droidVolume ? `Droid VolumeID: ${safe(parsed.droidVolume)}<br/>` : "";
      const droidObject = parsed.droidObject ? `Droid ObjectID: ${safe(parsed.droidObject)}<br/>` : "";
      const birthVolume = parsed.droidBirthVolume
        ? `Birth VolumeID: ${safe(parsed.droidBirthVolume)}<br/>`
        : "";
      const birthObject = parsed.droidBirthObject
        ? `Birth ObjectID: ${safe(parsed.droidBirthObject)}<br/>`
        : "";
      return (
        `<div class="smallNote" title="NTFS object tracking identifiers used by Distributed Link Tracking; Droid VolumeID is for link tracking and typically does not match System.VolumeId from the property store.">Tracker data: shell tracking IDs to find the target after moves/renames (Droid IDs are separate from System.VolumeId).<br/>` +
        `${machine}${droidVolume}${droidObject}${birthVolume}${birthObject}</div>`
      );
    }
    case 0xa0000009:
      return renderPropertyStore(block.parsed as LnkPropertyStoreData | null);
    case 0xa000000c: {
      const parsed = block.parsed as LnkVistaIdListData | null;
      if (!parsed) return "";
      const count = parsed.items?.length ?? 0;
      const terminator = parsed.terminatorPresent ? "" : " (no terminator)";
      return `<div class="smallNote">Vista+ IDList: ${count} item(s)${terminator}</div>`;
    }
    case 0xa0000004: {
      const parsed = block.parsed as { codePage?: number } | null;
      if (!parsed || parsed.codePage == null) return "";
      return `<div class="smallNote">Code page: ${parsed.codePage}</div>`;
    }
    case 0xa0000005: {
      const parsed = block.parsed as { folderId?: number; offset?: number } | null;
      if (parsed?.folderId == null || parsed.offset == null) return "";
      return `<div class="smallNote">Folder ID: ${parsed.folderId} (offset ${parsed.offset})</div>`;
    }
    case 0xa000000b: {
      const parsed = block.parsed as { knownFolderId?: string | null; offset?: number } | null;
      if (!parsed?.knownFolderId || parsed.offset == null) return "";
      return `<div class="smallNote">Known folder: ${safe(parsed.knownFolderId)} (offset ${parsed.offset})</div>`;
    }
    default:
      return "";
  }
};

export { describeBlock, renderPropertyStore };
