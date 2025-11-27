// @ts-nocheck
"use strict";

import { parseExtraData } from "./extra-data.js";
import { parseLinkInfo } from "./link-info.js";
import type { LnkParseResult } from "./types.js";
import {
  SHELL_LINK_CLSID,
  SHELL_LINK_HEADER_SIZE,
  describeHotKey,
  linkFlag,
  readCountedString,
  readFiletime,
  readGuid,
  showCommandName
} from "./utils.js";
import { parsePidlItems } from "./pidl.js";

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
  const bodyStart = offset + 2;
  const bodyEnd = Math.min(end, dv.byteLength);
  const { items, terminatorPresent } = parsePidlItems(dv, bodyStart, bodyEnd, warnings);
  const resolvedPath = buildPidlPath(items);
  return {
    size: idListSize,
    items,
    terminatorPresent,
    truncated: end > dv.byteLength,
    resolvedPath,
    totalSize: Math.min(idListSize + 2, dv.byteLength - offset)
  };
};

const buildPidlPath = items => {
  if (!Array.isArray(items) || !items.length) return null;
  const parts = [];
  const driveFromItem = item => {
    const text = item?.longName || item?.shortName;
    if (!text) return null;
    const match = text.match(/^([A-Za-z]):?/);
    return match ? `${match[1].toUpperCase()}:` : null;
  };
  const cleanSegment = text => (text ? text.replace(/[\\/]+/g, "").trim() : null);
  items.forEach(item => {
    if (!item || item.typeName === "Root") return;
    if (item.typeName === "Drive") {
      const drive = driveFromItem(item);
      if (drive) parts.push(drive);
      return;
    }
    const label = cleanSegment(item.longName || item.shortName);
    if (label) parts.push(label);
  });
  if (!parts.length) return null;
  const start = parts[0].endsWith(":") ? [parts.shift()] : [];
  return [...start, ...parts].join("\\");
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

export const hasShellLinkSignature = (dv: DataView): boolean =>
  dv.byteLength >= SHELL_LINK_HEADER_SIZE &&
  dv.getUint32(0, true) === SHELL_LINK_HEADER_SIZE &&
  readGuid(dv, 4) === SHELL_LINK_CLSID;

export async function parseLnk(file: File): Promise<LnkParseResult | null> {
  const buffer = await file.slice(0, file.size || 0).arrayBuffer();
  const dv = new DataView(buffer);
  const warnings = [];

  if (!hasShellLinkSignature(dv)) return null;
  const header = parseLinkHeader(dv, warnings);
  if (!header) return null;

  let cursor = SHELL_LINK_HEADER_SIZE;
  const idList = linkFlag(header.linkFlags, 0x1) ? parseIdList(dv, cursor, warnings) : null;
  if (idList) cursor += idList.totalSize;

  const linkInfo = parseLinkInfo(
    dv,
    cursor,
    warnings,
    linkFlag(header.linkFlags, 0x2) && !linkFlag(header.linkFlags, 0x100)
  );
  if (linkInfo?.size) cursor += linkInfo.size;

  const stringData = parseStringData(
    dv,
    cursor,
    header.linkFlags,
    warnings,
    linkFlag(header.linkFlags, 0x80)
  );
  cursor = stringData.endOffset || cursor;

  const extraData = parseExtraData(dv, cursor, warnings);
  const linkInfoBase = linkInfo?.localBasePathUnicode || linkInfo?.localBasePath || null;
  const linkInfoSuffix = linkInfo?.commonPathSuffixUnicode || linkInfo?.commonPathSuffix || null;
  const linkInfoPath =
    linkInfoBase || linkInfoSuffix
      ? [linkInfoBase, linkInfoSuffix && linkInfoBase ? linkInfoSuffix : null]
          .filter(Boolean)
          .join(linkInfoBase ? "\\" : "")
      : null;

  return {
    header,
    idList,
    linkInfo,
    stringData,
    extraData,
    warnings,
    linkInfoPath
  };
}
