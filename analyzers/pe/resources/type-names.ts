"use strict";

import { RESOURCE_DIRECTORY_OFFSET_MASK } from "./directory-format.js";
import type { ResourceTypeIdentity } from "./tree-types.js";

const resourceTypeNames: Readonly<Record<number, string>> = {
  1: "CURSOR", 2: "BITMAP", 3: "ICON", 4: "MENU", 5: "DIALOG", 6: "STRING", 7: "FONTDIR", 8: "FONT", 9: "ACCELERATOR",
  10: "RCDATA", 11: "MESSAGETABLE", 12: "GROUP_CURSOR", 14: "GROUP_ICON", 16: "VERSION", 17: "DLGINCLUDE", 19: "PLUGPLAY",
  20: "VXD", 21: "ANICURSOR", 22: "ANIICON", 23: "HTML", 24: "MANIFEST",
  // MFC conventions for application-defined types, rather than Win32 standard RT_* IDs.
  // https://github.com/adzm/atlmfc/blob/master/include/afxres.h
  28: "RIBBON_XML", 240: "DLGINIT", 241: "TOOLBAR"
};

export const knownResourceType = (id: number): string | null => resourceTypeNames[id] ?? null;

const knownResourceTypeIds = new Map(Object.entries(resourceTypeNames)
  .map(([id, name]) => [name, Number(id)]));

export const resourceTypeReferenceKey = (type: string): number | string => {
  const unknown = /^TYPE_(0|[1-9]\d{0,9})$/u.exec(type);
  const id = unknown ? Number(unknown[1]) : null;
  return knownResourceTypeIds.get(type) ??
    (id !== null && id <= RESOURCE_DIRECTORY_OFFSET_MASK && !knownResourceType(id) ? id : type);
};

// Groups supplied without a recorded key use the conventional decoder name.
export const resourceDecoderType = (group: ResourceTypeIdentity): string =>
  group.typeKey === undefined || group.typeKey === resourceTypeReferenceKey(group.typeName)
    ? group.typeName : "";
