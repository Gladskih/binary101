// @ts-nocheck
"use strict";

import {
  driveTypeName,
  linkFlag,
  providerTypeName,
  readNullTerminatedString
} from "./utils.js";

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

export const parseLinkInfo = (dv, offset, warnings, hasLinkInfo) => {
  if (!hasLinkInfo) return null;
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

  const checkOffset = (name, value) => {
    if (!value) return;
    if (value < headerSize) {
      warnings.push(`${name} offset (${value}) is smaller than LinkInfoHeaderSize (${headerSize}).`);
    }
  };
  checkOffset("VolumeID", volumeIdOffset);
  checkOffset("LocalBasePath", localBasePathOffset);
  checkOffset("CommonNetworkRelativeLink", commonNetworkRelativeLinkOffset);
  checkOffset("CommonPathSuffix", commonPathSuffixOffset);
  checkOffset("LocalBasePathUnicode", localBasePathOffsetUnicode);
  checkOffset("CommonPathSuffixUnicode", commonPathSuffixOffsetUnicode);

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
