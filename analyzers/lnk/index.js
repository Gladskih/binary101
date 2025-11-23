"use strict";

const SHELL_LINK_HEADER_SIZE = 0x4c;
const SHELL_LINK_CLSID = "00021401-0000-0000-c000-000000000046";
const FILETIME_TICKS_PER_MS = 10000n;
const FILETIME_EPOCH_BIAS_MS = 11644473600000n;
const UTF16_DECODER = new TextDecoder("utf-16le", { fatal: false });

const linkFlag = (flags, mask) => (flags & mask) !== 0;

const driveTypeName = driveType => {
  switch (driveType) {
    case 0:
      return "Unknown";
    case 1:
      return "No root directory";
    case 2:
      return "Removable drive";
    case 3:
      return "Fixed drive";
    case 4:
      return "Network drive";
    case 5:
      return "CD-ROM";
    case 6:
      return "RAM disk";
    default:
      return null;
  }
};

const providerTypeName = value => {
  switch (value) {
    case 0x001a0000:
      return "NetWare";
    case 0x001b0000:
      return "Vines";
    case 0x001c0000:
      return "MSNet";
    case 0x001f0000:
      return "VMNet";
    case 0x00200000:
      return "NetCray";
    case 0x00210000:
      return "CEF";
    case 0x00220000:
      return "SFS";
    case 0x002a0000:
      return "SMB (LanMan)";
    case 0x002b0000:
      return "DFS / WebDAV";
    case 0x00300000:
      return "NFS";
    default:
      return null;
  }
};

const showCommandName = value => {
  switch (value) {
    case 1:
      return "Normal window";
    case 3:
      return "Maximized";
    case 7:
      return "Minimized";
    default:
      return null;
  }
};

const hotKeyName = vk => {
  if (vk >= 0x41 && vk <= 0x5a) return String.fromCharCode(vk);
  if (vk >= 0x30 && vk <= 0x39) return String.fromCharCode(vk);
  if (vk >= 0x70 && vk <= 0x87) return `F${vk - 0x6f}`;
  const map = {
    0x08: "Backspace",
    0x09: "Tab",
    0x0d: "Enter",
    0x1b: "Esc",
    0x20: "Space",
    0x21: "PgUp",
    0x22: "PgDn",
    0x23: "End",
    0x24: "Home",
    0x25: "Left",
    0x26: "Up",
    0x27: "Right",
    0x28: "Down",
    0x2d: "Insert",
    0x2e: "Delete"
  };
  return map[vk] || null;
};

const describeHotKey = value => {
  if (!value) return null;
  const key = value & 0xff;
  const modifiers = value >> 8;
  const parts = [];
  if (modifiers & 0x01) parts.push("Shift");
  if (modifiers & 0x02) parts.push("Ctrl");
  if (modifiers & 0x04) parts.push("Alt");
  const keyLabel = hotKeyName(key) || `VK-${key.toString(16).padStart(2, "0")}`;
  parts.push(keyLabel);
  return parts.join("+");
};

const readGuid = (dv, offset) => {
  if (offset + 16 > dv.byteLength) return null;
  const data1 = dv.getUint32(offset, true).toString(16).padStart(8, "0");
  const data2 = dv.getUint16(offset + 4, true).toString(16).padStart(4, "0");
  const data3 = dv.getUint16(offset + 6, true).toString(16).padStart(4, "0");
  const b = [];
  for (let i = 0; i < 8; i += 1) {
    b.push(dv.getUint8(offset + 8 + i).toString(16).padStart(2, "0"));
  }
  return `${data1}-${data2}-${data3}-${b.slice(0, 2).join("")}-${b.slice(2).join("")}`.toLowerCase();
};

const decodeAnsi = bytes => {
  let out = "";
  for (let i = 0; i < bytes.length; i += 1) {
    const code = bytes[i];
    if (code === 0) break;
    out += String.fromCharCode(code);
  }
  return out;
};

const readFiletime = (dv, offset) => {
  if (offset + 8 > dv.byteLength || typeof dv.getBigUint64 !== "function") {
    return { raw: null, iso: null };
  }
  const raw = dv.getBigUint64(offset, true);
  if (raw === 0n) return { raw, iso: null };
  const ms = raw / FILETIME_TICKS_PER_MS - FILETIME_EPOCH_BIAS_MS;
  const msNumber = Number(ms);
  if (!Number.isFinite(msNumber)) return { raw, iso: null };
  const date = new Date(msNumber);
  const iso = date.toISOString();
  const year = date.getUTCFullYear();
  const taggedIso = year < 1980 || year > 2200 ? `${iso} (unusual)` : iso;
  return { raw, iso: taggedIso };
};

const readNullTerminatedString = (dv, offset, maxEnd, isUnicode) => {
  const limit = Math.min(maxEnd, dv.byteLength);
  if (offset >= limit) return "";
  if (isUnicode) {
    const codes = [];
    for (let i = offset; i + 1 < limit; i += 2) {
      const code = dv.getUint16(i, true);
      if (code === 0) break;
      codes.push(code);
    }
    return String.fromCharCode(...codes);
  }
  const bytes = [];
  for (let i = offset; i < limit; i += 1) {
    const code = dv.getUint8(i);
    if (code === 0) break;
    bytes.push(code);
  }
  return decodeAnsi(bytes);
};

const readCountedString = (dv, offset, isUnicode, warnings, label) => {
  if (offset + 2 > dv.byteLength) {
    warnings.push(`${label} length is truncated`);
    return { value: null, size: dv.byteLength - offset };
  }
  const charCount = dv.getUint16(offset, true);
  const charSize = isUnicode ? 2 : 1;
  const byteLength = charCount * charSize;
  const start = offset + 2;
  const end = start + byteLength;
  if (end > dv.byteLength) {
    warnings.push(`${label} content is truncated`);
    return { value: null, size: dv.byteLength - offset };
  }
  const bytes = new Uint8Array(dv.buffer, dv.byteOffset + start, byteLength);
  const value = isUnicode ? UTF16_DECODER.decode(bytes) : decodeAnsi(bytes);
  const trimmed = value.replace(/\0+$/, "");
  return { value: trimmed, size: byteLength + 2 };
};

const parseLinkHeader = (dv, warnings) => {
  if (dv.byteLength < SHELL_LINK_HEADER_SIZE) {
    warnings.push("Shell link header is truncated.");
    return null;
  }
  const headerSize = dv.getUint32(0, true);
  if (headerSize !== SHELL_LINK_HEADER_SIZE) {
    warnings.push(`Unexpected header size ${headerSize} (expected ${SHELL_LINK_HEADER_SIZE}).`);
  }
  const clsid = readGuid(dv, 4);
  if (clsid && clsid !== SHELL_LINK_CLSID) {
    warnings.push("LinkCLSID does not match the Shell Link format.");
  }
  const linkFlags = dv.getUint32(0x14, true);
  const fileAttributes = dv.getUint32(0x18, true);
  const creationTime = readFiletime(dv, 0x1c);
  const accessTime = readFiletime(dv, 0x24);
  const writeTime = readFiletime(dv, 0x2c);
  const fileSize = dv.getUint32(0x34, true);
  const iconIndex = dv.getUint32(0x38, true);
  const showCommand = dv.getUint32(0x3c, true);
  const hotKey = dv.getUint16(0x40, true);

  return {
    size: headerSize,
    clsid,
    linkFlags,
    fileAttributes,
    creationTime,
    accessTime,
    writeTime,
    fileSize,
    iconIndex,
    showCommand,
    showCommandName: showCommandName(showCommand),
    hotKey,
    hotKeyLabel: describeHotKey(hotKey)
  };
};

const parseIdList = (dv, offset, warnings) => {
  if (offset + 2 > dv.byteLength) {
    warnings.push("LinkTargetIDList length is truncated.");
    return { size: 0, items: [], truncated: true, totalSize: 0 };
  }
  const idListSize = dv.getUint16(offset, true);
  const end = offset + 2 + idListSize;
  if (end > dv.byteLength) {
    warnings.push("LinkTargetIDList extends beyond the file size.");
  }
  const items = [];
  let cursor = offset + 2;
  while (cursor + 2 <= Math.min(end, dv.byteLength)) {
    const itemSize = dv.getUint16(cursor, true);
    if (itemSize === 0) break;
    if (itemSize < 2) {
      warnings.push("Encountered malformed IDList item with size < 2.");
      break;
    }
    const itemEnd = cursor + itemSize;
    const truncated = itemEnd > dv.byteLength || itemEnd > end;
    items.push({
      size: itemSize,
      truncated,
      offset: cursor
    });
    if (truncated) break;
    cursor = itemEnd;
  }
  return {
    size: idListSize,
    items,
    truncated: end > dv.byteLength,
    totalSize: Math.min(idListSize + 2, dv.byteLength - offset)
  };
};

const parseVolumeId = (dv, start, maxEnd, warnings) => {
  if (start + 0x10 > maxEnd || start + 0x10 > dv.byteLength) {
    warnings.push("VolumeID is truncated.");
    return null;
  }
  const size = dv.getUint32(start, true);
  const end = start + size;
  const truncated = end > maxEnd || end > dv.byteLength;
  const driveType = dv.getUint32(start + 4, true);
  const driveSerialNumber = dv.getUint32(start + 8, true);
  const volumeLabelOffset = dv.getUint32(start + 12, true);
  const hasUnicodeOffset = size >= 0x14;
  const volumeLabelOffsetUnicode = hasUnicodeOffset ? dv.getUint32(start + 16, true) : null;
  const labelAnsi =
    volumeLabelOffset > 0
      ? readNullTerminatedString(dv, start + volumeLabelOffset, end, false)
      : null;
  const labelUnicode =
    hasUnicodeOffset && volumeLabelOffsetUnicode > 0
      ? readNullTerminatedString(dv, start + volumeLabelOffsetUnicode, end, true)
      : null;
  return {
    size,
    driveType,
    driveTypeName: driveTypeName(driveType),
    driveSerialNumber,
    volumeLabel: labelUnicode || labelAnsi || null,
    labelAnsi,
    labelUnicode,
    truncated
  };
};

const parseCommonNetworkRelativeLink = (dv, start, maxEnd, warnings) => {
  if (start + 0x14 > maxEnd || start + 0x14 > dv.byteLength) {
    warnings.push("CommonNetworkRelativeLink is truncated.");
    return null;
  }
  const size = dv.getUint32(start, true);
  const end = start + size;
  const truncated = end > maxEnd || end > dv.byteLength;
  const flags = dv.getUint32(start + 4, true);
  const netNameOffset = dv.getUint32(start + 8, true);
  const deviceNameOffset = dv.getUint32(start + 12, true);
  const networkProviderType = dv.getUint32(start + 16, true);
  const hasUnicodeOffsets = size >= 0x1c;
  const netNameOffsetUnicode = hasUnicodeOffsets ? dv.getUint32(start + 0x14, true) : null;
  const deviceNameOffsetUnicode = hasUnicodeOffsets ? dv.getUint32(start + 0x18, true) : null;
  const netName =
    netNameOffset > 0 ? readNullTerminatedString(dv, start + netNameOffset, end, false) : null;
  const deviceName =
    deviceNameOffset > 0
      ? readNullTerminatedString(dv, start + deviceNameOffset, end, false)
      : null;
  const netNameUnicode =
    netNameOffsetUnicode && netNameOffsetUnicode > 0
      ? readNullTerminatedString(dv, start + netNameOffsetUnicode, end, true)
      : null;
  const deviceNameUnicode =
    deviceNameOffsetUnicode && deviceNameOffsetUnicode > 0
      ? readNullTerminatedString(dv, start + deviceNameOffsetUnicode, end, true)
      : null;
  return {
    size,
    flags,
    netName: netNameUnicode || netName || null,
    netNameAnsi: netName,
    netNameUnicode,
    deviceName: deviceNameUnicode || deviceName || null,
    deviceNameAnsi: deviceName,
    deviceNameUnicode,
    networkProviderType,
    networkProviderName: providerTypeName(networkProviderType),
    truncated
  };
};

const parseLinkInfo = (dv, offset, warnings) => {
  if (offset + 4 > dv.byteLength) {
    warnings.push("LinkInfo size is truncated.");
    return { size: 0, truncated: true };
  }
  const size = dv.getUint32(offset, true);
  if (size === 0) return { size: 0 };
  const end = offset + size;
  const truncated = end > dv.byteLength;
  const headerSize = offset + 8 <= dv.byteLength ? dv.getUint32(offset + 4, true) : 0;
  if (headerSize < 0x1c) warnings.push("LinkInfoHeaderSize is smaller than expected.");
  const flags = offset + 0x0c <= dv.byteLength ? dv.getUint32(offset + 0x08, true) : 0;
  const volumeIdOffset =
    offset + 0x10 <= dv.byteLength ? dv.getUint32(offset + 0x0c, true) : 0;
  const localBasePathOffset =
    offset + 0x14 <= dv.byteLength ? dv.getUint32(offset + 0x10, true) : 0;
  const commonNetworkRelativeLinkOffset =
    offset + 0x18 <= dv.byteLength ? dv.getUint32(offset + 0x14, true) : 0;
  const commonPathSuffixOffset =
    offset + 0x1c <= dv.byteLength ? dv.getUint32(offset + 0x18, true) : 0;
  const hasUnicodeOffsets = headerSize >= 0x24;
  const localBasePathOffsetUnicode =
    hasUnicodeOffsets && offset + 0x20 <= dv.byteLength
      ? dv.getUint32(offset + 0x1c, true)
      : null;
  const commonPathSuffixOffsetUnicode =
    hasUnicodeOffsets && offset + 0x24 <= dv.byteLength
      ? dv.getUint32(offset + 0x20, true)
      : null;

  const volume =
    linkFlag(flags, 0x1) && volumeIdOffset
      ? parseVolumeId(dv, offset + volumeIdOffset, end, warnings)
      : null;
  const localBasePath =
    localBasePathOffset > 0
      ? readNullTerminatedString(dv, offset + localBasePathOffset, end, false)
      : null;
  const localBasePathUnicode =
    localBasePathOffsetUnicode && localBasePathOffsetUnicode > 0
      ? readNullTerminatedString(dv, offset + localBasePathOffsetUnicode, end, true)
      : null;
  const commonPathSuffix =
    commonPathSuffixOffset > 0
      ? readNullTerminatedString(dv, offset + commonPathSuffixOffset, end, false)
      : null;
  const commonPathSuffixUnicode =
    commonPathSuffixOffsetUnicode && commonPathSuffixOffsetUnicode > 0
      ? readNullTerminatedString(dv, offset + commonPathSuffixOffsetUnicode, end, true)
      : null;

  const network =
    linkFlag(flags, 0x2) && commonNetworkRelativeLinkOffset
      ? parseCommonNetworkRelativeLink(
        dv,
        offset + commonNetworkRelativeLinkOffset,
        end,
        warnings
      )
      : null;

  return {
    size,
    headerSize,
    flags,
    truncated,
    volume,
    localBasePath,
    localBasePathUnicode,
    commonPathSuffix,
    commonPathSuffixUnicode,
    network
  };
};

const parseStringData = (dv, offset, linkFlags, warnings, isUnicode) => {
  const strings = {};
  let cursor = offset;
  const readIf = (mask, field) => {
    if (!linkFlag(linkFlags, mask)) return;
    const { value, size } = readCountedString(dv, cursor, isUnicode, warnings, field);
    cursor += size;
    if (value != null) strings[field] = value;
  };
  readIf(0x00000004, "name");
  readIf(0x00000008, "relativePath");
  readIf(0x00000010, "workingDir");
  readIf(0x00000020, "arguments");
  readIf(0x00000040, "iconLocation");
  return { ...strings, size: cursor - offset, endOffset: cursor };
};

const nameForExtraBlock = signature => {
  switch (signature >>> 0) {
    case 0xa0000001:
      return "Environment variables";
    case 0xa0000002:
      return "Console properties";
    case 0xa0000003:
      return "Tracker data";
    case 0xa0000004:
      return "Console code page";
    case 0xa0000005:
      return "Special folder";
    case 0xa0000006:
      return "Darwin data";
    case 0xa0000007:
      return "Icon environment";
    case 0xa0000008:
      return "Shim data";
    case 0xa0000009:
      return "Property store";
    case 0xa000000b:
      return "Known folder";
    case 0xa000000c:
      return "Vista+ IDList";
    default:
      return null;
  }
};

const parseFixedStringBlock = blockDv => {
  const ansi = readNullTerminatedString(blockDv, 8, Math.min(blockDv.byteLength, 8 + 260), false);
  const unicode = readNullTerminatedString(
    blockDv,
    8 + 260,
    Math.min(blockDv.byteLength, 8 + 260 + 520),
    true
  );
  return { ansi: ansi || null, unicode: unicode || null };
};

const parseKnownFolderBlock = blockDv => {
  if (blockDv.byteLength < 0x1c) return null;
  const guid = readGuid(blockDv, 8);
  const offset = blockDv.getUint32(0x18, true);
  return { knownFolderId: guid, offset };
};

const parseSpecialFolderBlock = blockDv => {
  if (blockDv.byteLength < 0x10) return null;
  const folderId = blockDv.getUint32(8, true);
  const offset = blockDv.getUint32(12, true);
  return { folderId, offset };
};

const parseConsoleFeBlock = blockDv => {
  if (blockDv.byteLength < 0x0c) return null;
  return { codePage: blockDv.getUint16(8, true) };
};

const parseExtraBlock = (signature, blockDv) => {
  switch (signature >>> 0) {
    case 0xa0000001:
    case 0xa0000006:
    case 0xa0000007:
      return parseFixedStringBlock(blockDv);
    case 0xa0000004:
      return parseConsoleFeBlock(blockDv);
    case 0xa0000005:
      return parseSpecialFolderBlock(blockDv);
    case 0xa000000b:
      return parseKnownFolderBlock(blockDv);
    default:
      return null;
  }
};

const parseExtraData = (dv, offset, warnings) => {
  const blocks = [];
  let cursor = offset;
  while (cursor + 4 <= dv.byteLength) {
    const size = dv.getUint32(cursor, true);
    if (size === 0) break;
    if (size < 8) {
      warnings.push("Encountered malformed ExtraData block smaller than header size.");
      break;
    }
    const signature = dv.getUint32(cursor + 4, true);
    const blockEnd = cursor + size;
    const clampedEnd = Math.min(blockEnd, dv.byteLength);
    const blockDv = new DataView(dv.buffer, dv.byteOffset + cursor, clampedEnd - cursor);
    blocks.push({
      size,
      signature,
      name: nameForExtraBlock(signature),
      truncated: blockEnd > dv.byteLength,
      parsed: parseExtraBlock(signature, blockDv)
    });
    if (blockEnd > dv.byteLength) break;
    cursor = blockEnd;
  }
  return { blocks, endOffset: cursor };
};

export const hasShellLinkSignature = dv =>
  dv.byteLength >= SHELL_LINK_HEADER_SIZE &&
  dv.getUint32(0, true) === SHELL_LINK_HEADER_SIZE &&
  readGuid(dv, 4) === SHELL_LINK_CLSID;

export async function parseLnk(file) {
  const buffer = await file.slice(0, file.size || 0).arrayBuffer();
  const dv = new DataView(buffer);
  const warnings = [];

  if (!hasShellLinkSignature(dv)) return null;
  const header = parseLinkHeader(dv, warnings);
  if (!header) return null;

  let cursor = SHELL_LINK_HEADER_SIZE;
  const idList = linkFlag(header.linkFlags, 0x1) ? parseIdList(dv, cursor, warnings) : null;
  if (idList) cursor += idList.totalSize;

  let linkInfo = null;
  if (linkFlag(header.linkFlags, 0x2) && !linkFlag(header.linkFlags, 0x100)) {
    linkInfo = parseLinkInfo(dv, cursor, warnings);
    if (linkInfo?.size) cursor += linkInfo.size;
  }

  const stringData = parseStringData(dv, cursor, header.linkFlags, warnings, linkFlag(header.linkFlags, 0x80));
  cursor = stringData.endOffset || cursor;

  const extraData = parseExtraData(dv, cursor, warnings);

  return {
    header,
    idList,
    linkInfo,
    stringData,
    extraData,
    warnings
  };
}
