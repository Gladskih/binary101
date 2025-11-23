"use strict";

import { dd, rowFlags, safe } from "../../html-utils.js";
import { formatHumanSize, toHex32 } from "../../binary-utils.js";

const LINK_FLAGS = [
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

const FILE_ATTRIBUTE_FLAGS = [
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

const LINKINFO_FLAGS = [
  [0x00000001, "Volume ID + local base"],
  [0x00000002, "Network relative link"]
];

const formatTime = value => value?.iso || "-";
const formatSize = value => (value ? formatHumanSize(value) : "-");

const buildTargetPath = lnk => {
  const info = lnk.linkInfo || {};
  const base = info.localBasePathUnicode || info.localBasePath;
  const suffix = info.commonPathSuffixUnicode || info.commonPathSuffix;
  if (base && suffix) return base.endsWith("\\") ? `${base}${suffix}` : `${base}\\${suffix}`;
  if (base) return base;
  if (suffix) return suffix;
  const strings = lnk.stringData || {};
  if (strings.relativePath) return strings.relativePath;
  if (strings.workingDir && strings.arguments) return `${strings.workingDir} ${strings.arguments}`;
  return null;
};

const renderSummary = (lnk, out) => {
  const header = lnk.header || {};
  const target = buildTargetPath(lnk);
  out.push(`<section>`);
  out.push(`<h4 style="margin:0 0 .5rem 0;font-size:.9rem">Shortcut overview</h4>`);
  out.push(`<dl>`);
  out.push(dd("Target", safe(target || "(not specified)")));
  out.push(dd("Working directory", safe(lnk.stringData?.workingDir || lnk.linkInfo?.localBasePath || "-")));
  out.push(dd("Arguments", safe(lnk.stringData?.arguments || "-")));
  const showCommand = header.showCommandName || header.showCommand || "-";
  out.push(dd("Show command", safe(showCommand)));
  out.push(dd("Hotkey", safe(header.hotKeyLabel || "-")));
  out.push(dd("Icon index", header.iconIndex != null ? header.iconIndex.toString() : "-"));
  out.push(`</dl>`);
  out.push(`</section>`);
};

const renderHeader = (lnk, out) => {
  const header = lnk.header || {};
  out.push(`<section>`);
  out.push(`<h4 style="margin:0 0 .5rem 0;font-size:.9rem">Shell link header</h4>`);
  out.push(`<dl>`);
  out.push(dd("LinkCLSID", safe(header.clsid || "-")));
  out.push(dd("File size", formatSize(header.fileSize)));
  out.push(dd("Flags", rowFlags(header.linkFlags || 0, LINK_FLAGS)));
  out.push(dd("File attributes", rowFlags(header.fileAttributes || 0, FILE_ATTRIBUTE_FLAGS)));
  out.push(dd("Created", safe(formatTime(header.creationTime))));
  out.push(dd("Accessed", safe(formatTime(header.accessTime))));
  out.push(dd("Modified", safe(formatTime(header.writeTime))));
  out.push(`</dl>`);
  out.push(`</section>`);
};

const renderVolumeInfo = volume => {
  if (!volume) return "-";
  const out = [];
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

const renderNetworkInfo = network => {
  if (!network) return "";
  const parts = [];
  parts.push(`<div class="smallNote">`);
  if (network.netName) parts.push(`Network path: ${safe(network.netName)}<br/>`);
  if (network.deviceName) parts.push(`Device: ${safe(network.deviceName)}<br/>`);
  const provider =
    network.networkProviderName || (network.networkProviderType != null ? toHex32(network.networkProviderType, 8) : null);
  if (provider) parts.push(`Provider: ${safe(provider)}<br/>`);
  if (network.truncated) parts.push(`<span class="smallNote">Network data truncated</span>`);
  parts.push(`</div>`);
  return parts.join("");
};

const renderLinkInfo = (lnk, out) => {
  const info = lnk.linkInfo;
  if (!info) return;
  out.push(`<section>`);
  out.push(`<h4 style="margin:0 0 .5rem 0;font-size:.9rem">LinkInfo</h4>`);
  out.push(`<dl>`);
  out.push(dd("Flags", rowFlags(info.flags || 0, LINKINFO_FLAGS)));
  out.push(dd("Local base path", safe(info.localBasePathUnicode || info.localBasePath || "-")));
  out.push(dd("Common path suffix", safe(info.commonPathSuffixUnicode || info.commonPathSuffix || "-")));
  out.push(dd("Volume", renderVolumeInfo(info.volume)));
  out.push(dd("Network", renderNetworkInfo(info.network) || "-"));
  if (info.truncated) {
    out.push(`<div class="smallNote">LinkInfo extends beyond file size.</div>`);
  }
  out.push(`</dl>`);
  out.push(`</section>`);
};

const renderStrings = (lnk, out) => {
  const s = lnk.stringData || {};
  const keys = ["name", "relativePath", "workingDir", "arguments", "iconLocation"];
  const hasValue = keys.some(key => s[key]);
  if (!hasValue) return;
  out.push(`<section>`);
  out.push(`<h4 style="margin:0 0 .5rem 0;font-size:.9rem">String data</h4>`);
  out.push(`<dl>`);
  keys.forEach(key => {
    if (s[key]) out.push(dd(key, safe(s[key])));
  });
  out.push(`</dl>`);
  out.push(`</section>`);
};

const renderIdList = (lnk, out) => {
  const idList = lnk.idList;
  if (!idList) return;
  out.push(`<section>`);
  out.push(`<h4 style="margin:0 0 .5rem 0;font-size:.9rem">LinkTargetIDList</h4>`);
  out.push(`<dl>`);
  out.push(dd("Size", `${idList.size} bytes`));
  out.push(dd("Items", idList.items?.length ? idList.items.length.toString() : "0"));
  if (idList.truncated) out.push(`<div class="smallNote">ID list truncated</div>`);
  out.push(`</dl>`);
  out.push(`</section>`);
};

const describeBlock = block => {
  if (!block.parsed) return "";
  if (block.parsed.ansi || block.parsed.unicode) {
    const ansi = block.parsed.ansi ? safe(block.parsed.ansi) : "-";
    const unicode = block.parsed.unicode ? safe(block.parsed.unicode) : "-";
    return `<div class="smallNote">ANSI: ${ansi}<br/>Unicode: ${unicode}</div>`;
  }
  if (block.parsed.codePage != null) {
    return `<div class="smallNote">Code page: ${block.parsed.codePage}</div>`;
  }
  if (block.parsed.folderId != null) {
    return `<div class="smallNote">Folder ID: ${block.parsed.folderId} (offset ${block.parsed.offset})</div>`;
  }
  if (block.parsed.knownFolderId) {
    return `<div class="smallNote">Known folder: ${safe(block.parsed.knownFolderId)} (offset ${block.parsed.offset})</div>`;
  }
  return "";
};

const renderExtraData = (lnk, out) => {
  const blocks = lnk.extraData?.blocks || [];
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
  out.push(`</section>`);
};

const renderWarnings = (lnk, out) => {
  const issues = lnk.warnings || [];
  if (!issues.length) return;
  out.push(`<section>`);
  out.push(`<h4 style="margin:0 0 .5rem 0;font-size:.9rem">Notices</h4>`);
  out.push(`<ul>`);
  issues.forEach(issue => out.push(`<li>${safe(issue)}</li>`));
  out.push(`</ul>`);
  out.push(`</section>`);
};

export function renderLnk(lnk) {
  if (!lnk) return "";
  const out = [];
  renderSummary(lnk, out);
  renderHeader(lnk, out);
  renderLinkInfo(lnk, out);
  renderStrings(lnk, out);
  renderIdList(lnk, out);
  renderExtraData(lnk, out);
  renderWarnings(lnk, out);
  return out.join("");
}
