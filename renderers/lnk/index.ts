"use strict";
/* eslint-disable max-lines */

import { dd, rowFlags, rowOpts, safe } from "../../html-utils.js";
import { formatHumanSize, toHex32 } from "../../binary-utils.js";
import type {
  LnkExtraDataBlock,
  LnkIdList,
  LnkLinkInfo,
  LnkParseResult,
  LnkProperty,
  LnkPropertyStorage,
  LnkPropertyStoreData,
  LnkStringData,
  LnkTrackerData,
  LnkVistaIdListData
} from "../../analyzers/lnk/types.js";

const LINK_FLAGS: Array<[number, string, string?]> = [
  [0x00000001, "Has ID list", "LinkTargetIDList present"],
  [0x00000002, "Has LinkInfo", "LinkInfo structure present"],
  [0x00000004, "Has name"],
  [0x00000008, "Has relative path"],
  [0x00000010, "Has working dir"],
  [0x00000020, "Has arguments"],
  [0x00000040, "Has icon location"],
  [0x00000080, "Unicode strings"],
  [0x00000100, "Force no LinkInfo"],
  [0x00000200, "Has environment path"],
  [0x00000400, "Run separately"],
  [0x00001000, "Has Darwin ID"],
  [0x00002000, "Run as different user"],
  [0x00004000, "Has expanded icon"],
  [0x00008000, "No PIDL alias"],
  [0x00020000, "Shim layer"],
  [0x00080000, "Enable metadata"],
  [0x02000000, "Prefer environment path"]
];

const FILE_ATTRIBUTE_FLAGS: Array<[number, string, string?]> = [
  [0x00000001, "Read-only"],
  [0x00000002, "Hidden"],
  [0x00000004, "System"],
  [0x00000010, "Directory"],
  [0x00000020, "Archive"],
  [0x00000040, "Device"],
  [0x00000080, "Normal"],
  [0x00000100, "Temporary"],
  [0x00000200, "Sparse"],
  [0x00000400, "Reparse point"],
  [0x00000800, "Compressed"],
  [0x00001000, "Offline"],
  [0x00002000, "Not indexed"],
  [0x00004000, "Encrypted"],
  [0x00008000, "Integrity stream"],
  [0x00010000, "Virtual"],
  [0x00020000, "No scrub data"]
];

const LINKINFO_FLAGS: Array<[number, string, string?]> = [
  [0x00000001, "Volume ID + local base"],
  [0x00000002, "Network relative link"]
];

const SHOW_COMMAND_OPTIONS: Array<[number, string]> = [
  [1, "Normal window"],
  [3, "Maximized"],
  [7, "Minimized"]
];

type LnkStringField = keyof Omit<LnkStringData, "size" | "endOffset">;

const formatTime = (value: { iso: string | null } | null | undefined): string =>
  value?.iso || "-";
const formatSize = (value: number | null | undefined): string =>
  value ? formatHumanSize(value) : "-";

const renderHint = (text: string): string => `<div class="smallNote">${safe(text)}</div>`;

const renderHeader = (lnk: LnkParseResult, out: string[]): void => {
  const { header } = lnk;
  out.push(`<section>`);
  out.push(`<h4 style="margin:0 0 .5rem 0;font-size:.9rem">Shell link header</h4>`);
  out.push(`<dl>`);
  const clsidText = header.clsid || "-";
  const clsidTitle =
    "COM class identifier for Shell Link objects; 00021401-0000-0000-c000-000000000046 is the standard Shell Link CLSID.";
  out.push(dd("LinkCLSID", `<span title="${safe(clsidTitle)}">${safe(clsidText)}</span>`));
  out.push(dd("File size", formatSize(header.fileSize)));
  out.push(dd("Flags", rowFlags(header.linkFlags || 0, LINK_FLAGS)));
  out.push(dd("File attributes", rowFlags(header.fileAttributes || 0, FILE_ATTRIBUTE_FLAGS)));
  out.push(dd("Created", safe(formatTime(header.creationTime))));
  out.push(dd("Accessed", safe(formatTime(header.accessTime))));
  out.push(dd("Modified", safe(formatTime(header.writeTime))));

  const showCommandValue = header.showCommand;
  const showCommandRow =
    showCommandValue != null ? rowOpts(showCommandValue, SHOW_COMMAND_OPTIONS) : "-";
  out.push(dd("Show command", showCommandRow));

  out.push(dd("Hotkey", safe(header.hotKeyLabel || "-")));

  let iconIndexHtml = "-";
  if (header.iconIndex != null) {
    const iconTitle =
      "Index of the icon within the icon location or target file; 0 refers to the first icon resource.";
    iconIndexHtml = `<span title="${safe(iconTitle)}">${safe(
      header.iconIndex.toString()
    )}</span>`;
  }
  out.push(dd("Icon index", iconIndexHtml));

  out.push(`</dl>`);
  out.push(
    renderHint(
      "Timestamps are stored as Windows FILETIME values in UTC. They describe the link's target when available; all zeros means \"not set.\""
    )
  );
  out.push(
    renderHint(
      "Flags gate the optional sections that follow (ID list, LinkInfo, strings, extra blocks). If a field looks empty, check whether its flag was set."
    )
  );
  out.push(
    renderHint(
      "LinkCLSID identifies the COM class used for Shell Link objects; the standard value 00021401-0000-0000-c000-000000000046 must be present for a valid .lnk file."
    )
  );
  out.push(`</section>`);
};

const renderVolumeInfo = (volume: LnkLinkInfo["volume"]): string => {
  if (!volume) return "-";
  const out: string[] = [];
  out.push(`<div class="smallNote">`);
  out.push(`Drive type: ${safe(volume.driveTypeName || "-")}<br/>`);
  out.push(
    `Serial: ${
      volume.driveSerialNumber != null ? safe(toHex32(volume.driveSerialNumber, 8)) : "-"
    }`
  );
  if (volume.volumeLabel) {
    out.push(`<br/>Label: ${safe(volume.volumeLabel)}`);
  }
  if (volume.truncated) {
    out.push(`<br/><span class="smallNote">VolumeID truncated</span>`);
  }
  out.push(`</div>`);
  return out.join("");
};

const renderNetworkInfo = (network: LnkLinkInfo["network"]): string => {
  if (!network) return "";
  const parts: string[] = [];
  parts.push(`<div class="smallNote">`);
  if (network.netName) parts.push(`Network path: ${safe(network.netName)}<br/>`);
  if (network.deviceName) parts.push(`Device: ${safe(network.deviceName)}<br/>`);
  const provider =
    network.networkProviderName ||
    (network.networkProviderType != null ? toHex32(network.networkProviderType, 8) : null);
  if (provider) parts.push(`Provider: ${safe(provider)}<br/>`);
  if (network.truncated) parts.push(`<span class="smallNote">Network data truncated</span>`);
  parts.push(`</div>`);
  return parts.join("");
};

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

const renderLinkInfo = (lnk: LnkParseResult, out: string[]): void => {
  const info = lnk.linkInfo;
  if (!info) return;
  out.push(`<section>`);
  out.push(`<h4 style="margin:0 0 .5rem 0;font-size:.9rem">LinkInfo</h4>`);
  out.push(`<dl>`);
  out.push(dd("Flags", rowFlags(info.flags || 0, LINKINFO_FLAGS)));
  if (info.localBasePath != null) {
    out.push(dd("LocalBasePath (ANSI)", safe(info.localBasePath)));
  }
  if (info.localBasePathUnicode) {
    out.push(dd("LocalBasePathUnicode (UTF-16LE)", safe(info.localBasePathUnicode)));
  }
  if (info.commonPathSuffix != null) {
    out.push(dd("CommonPathSuffix (ANSI)", safe(info.commonPathSuffix)));
  }
  if (info.commonPathSuffixUnicode) {
    out.push(dd("CommonPathSuffixUnicode (UTF-16LE)", safe(info.commonPathSuffixUnicode)));
  }
  out.push(dd("Volume", renderVolumeInfo(info.volume)));
  out.push(dd("Network", renderNetworkInfo(info.network) || "-"));
  const base = info.localBasePathUnicode || info.localBasePath;
  const suffix = info.commonPathSuffixUnicode || info.commonPathSuffix;
  let resolved = null;
  if (base && suffix) {
    resolved = base.endsWith("\\") ? `${base}${suffix}` : `${base}\\${suffix}`;
  } else if (base) {
    resolved = base;
  } else if (suffix) {
    resolved = suffix;
  }
  if (resolved) {
    out.push(dd("LocalBasePath + CommonPathSuffix", safe(resolved)));
  }
  if (info.truncated) {
    out.push(`<div class="smallNote">LinkInfo extends beyond file size.</div>`);
  }
  out.push(`</dl>`);
  out.push(
    renderHint(
      "Local base + common suffix build the resolved path on disk. If the link points to a network location, CommonNetworkRelativeLink carries the UNC/share details instead."
    )
  );
  out.push(`</section>`);
};

const renderStrings = (lnk: LnkParseResult, out: string[]): void => {
  const s = lnk.stringData;
  const keys: LnkStringField[] = ["name", "relativePath", "workingDir", "arguments", "iconLocation"];
  const hasValue = keys.some(key => Boolean(s[key]));
  if (!hasValue) return;
  out.push(`<section>`);
  out.push(`<h4 style="margin:0 0 .5rem 0;font-size:.9rem">String data</h4>`);
  out.push(`<dl>`);
  keys.forEach(key => {
    const value = s[key];
    if (value) out.push(dd(key, safe(value)));
  });
  out.push(`</dl>`);
  out.push(
    renderHint(
      "String data is stored as counted strings (length + characters). When Unicode flag is set, they are UTF-16LE; otherwise ANSI codepage from the creating system."
    )
  );
  out.push(`</section>`);
};

const renderIdList = (lnk: LnkParseResult, out: string[]): void => {
  const idList: LnkIdList | null = lnk.idList;
  if (!idList) return;
  out.push(`<section>`);
  out.push(`<h4 style="margin:0 0 .5rem 0;font-size:.9rem">LinkTargetIDList</h4>`);
  out.push(`<dl>`);
  out.push(dd("Size", `${idList.size} bytes`));
  const itemCount = idList.items?.length ? idList.items.length.toString() : "0";
  out.push(dd("Items", itemCount));
  if (idList.truncated) out.push(`<div class="smallNote">ID list truncated</div>`);
  out.push(`</dl>`);
  if (idList.items?.length) {
    out.push(
      `<table class="table"><thead><tr><th>#</th><th>Type</th><th>Short name</th><th>Long name</th><th title="File size from the file entry shell item; 0 for folders; not the .lnk size">Size</th><th>Modified (UTC)</th><th>Attributes</th></tr></thead><tbody>`
    );
    idList.items.forEach(item => {
      const typeLabel = item.typeName || item.typeHex || "-";
      const typeTitle = item.typeHex ? `${typeLabel} (${item.typeHex})` : typeLabel;
      out.push(
        `<tr><td>${item.index ?? ""}</td>` +
          `<td title="${safe(typeTitle)}">${safe(typeLabel)}</td>` +
          `<td title="DOS 8.3 short name">${safe(item.shortName || "-")}</td>` +
          `<td title="Decoded from BEEF0004 extension">${safe(item.longName || "-")}</td>` +
          `<td>${item.fileSize != null ? item.fileSize.toString() : "-"}</td>` +
          `<td>${safe(item.modified || "-")}</td>` +
          `<td title="File attributes">${item.attributes != null ? safe(toHex32(item.attributes, 4)) : "-"}</td>` +
        `</tr>`
      );
    });
    out.push(`</tbody></table>`);
  }
  out.push(
    renderHint(
      "ID lists are shell item IDs (PIDLs) that describe the target in shell terms. Each item is a segment (root, drive, folder, file); Control Panel or special folders are also expressed this way. Short name is the DOS 8.3 name; Long name is taken from the BEEF0004 extension when present. Size comes from the file entry shell item header and reflects the target file size (0 for folders), not the .lnk file size or a field width."
    )
  );
  out.push(`</section>`);
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

const renderExtraData = (lnk: LnkParseResult, out: string[]): void => {
  const blocks: LnkExtraDataBlock[] = lnk.extraData?.blocks ?? [];
  if (!blocks.length) return;
  out.push(`<section>`);
  out.push(`<h4 style="margin:0 0 .5rem 0;font-size:.9rem">Extra data blocks</h4>`);
  out.push(`<ul>`);
  blocks.forEach(block => {
    const name = block.name || "Unknown block";
    const sig = toHex32(block.signature >>> 0, 8);
    const note = block.truncated ? " (truncated)" : "";
    out.push(
      `<li>${safe(name)} ${safe(sig)} - ${block.size} bytes${note}${describeBlock(block)}</li>`
    );
  });
  out.push(`</ul>`);
  out.push(
    renderHint(
      "Extra data blocks carry optional hints for newer Windows versions: environment path variants, known folders, property stores, console settings, or other metadata. Tracker data (0xa0000003) holds shell tracking IDs and machine/volume hints used to find the target after moves/renames. Each block starts with a size and signature; unknown signatures come from shell extensions, and truncation often means the shortcut was cut short during copy/download."
    )
  );
  out.push(`</section>`);
};

const renderWarnings = (lnk: LnkParseResult, out: string[]): void => {
  const issues = lnk.warnings || [];
  if (!issues.length) return;
  out.push(`<section>`);
  out.push(`<h4 style="margin:0 0 .5rem 0;font-size:.9rem">Notices</h4>`);
  out.push(`<ul>`);
  issues.forEach(issue => out.push(`<li>${safe(issue)}</li>`));
  out.push(`</ul>`);
  out.push(`</section>`);
};

export function renderLnk(lnk: LnkParseResult | null): string {
  if (!lnk) return "";
  const out: string[] = [];
  out.push(
    `<p class="smallNote">Windows shortcuts store multiple ways to reach a target: shell item IDs (PIDLs), plain paths, and optional network or environment-based fallbacks. Flags below tell which pieces are present.</p>`
  );
  renderHeader(lnk, out);
  renderLinkInfo(lnk, out);
  renderStrings(lnk, out);
  renderIdList(lnk, out);
  renderExtraData(lnk, out);
  renderWarnings(lnk, out);
  return out.join("");
}
