"use strict";

export interface LnkFiletime {
  raw: bigint | null;
  iso: string | null;
}

export interface LnkHeader {
  size: number;
  clsid: string | null;
  linkFlags: number;
  fileAttributes: number;
  creationTime: LnkFiletime;
  accessTime: LnkFiletime;
  writeTime: LnkFiletime;
  fileSize: number;
  iconIndex: number;
  showCommand: number;
  showCommandName: string | null;
  hotKey: number;
  hotKeyLabel: string | null;
}

export interface LnkStringData {
  name?: string;
  relativePath?: string;
  workingDir?: string;
  arguments?: string;
  iconLocation?: string;
  size: number;
  endOffset: number;
}

export interface LnkExtensionBlock {
  size: number;
  signature: number;
  longName: string | null;
  truncated: boolean;
}

export interface LnkIdListItem {
  index: number;
  size: number;
  typeByte: number | null;
  typeName: string | null;
  typeHex: string | null;
  fileSize: number | null;
  modified: string | null;
  attributes: number | null;
  shortName: string | null;
  longName: string | null;
  extensionBlocks: LnkExtensionBlock[];
  clsid: string | null;
  truncated: boolean;
}

export interface LnkIdList {
  size: number;
  items: LnkIdListItem[];
  terminatorPresent: boolean;
  truncated: boolean;
  resolvedPath: string | null;
  totalSize: number;
}

export interface LnkVolumeInfo {
  size: number;
  driveType: number;
  driveTypeName: string | null;
  driveSerialNumber: number;
  volumeLabel: string | null;
  labelAnsi: string | null;
  labelUnicode: string | null;
  truncated: boolean;
}

export interface LnkNetworkInfo {
  size: number;
  flags: number;
  netName: string | null;
  netNameAnsi: string | null;
  netNameUnicode: string | null;
  deviceName: string | null;
  deviceNameAnsi: string | null;
  deviceNameUnicode: string | null;
  networkProviderType: number;
  networkProviderName: string | null;
  truncated: boolean;
}

export interface LnkLinkInfo {
  size: number;
  headerSize?: number;
  flags?: number;
  truncated?: boolean;
  volume?: LnkVolumeInfo | null;
  localBasePath?: string | null;
  localBasePathUnicode?: string | null;
  commonPathSuffix?: string | null;
  commonPathSuffixUnicode?: string | null;
  network?: LnkNetworkInfo | null;
}

export interface LnkEnvironmentStrings {
  ansi: string | null;
  unicode: string | null;
}

export interface LnkKnownFolderData {
  knownFolderId: string | null;
  offset: number;
}

export interface LnkSpecialFolderData {
  folderId: number;
  offset: number;
}

export interface LnkTrackerData {
  length: number | null;
  version: number | null;
  machineId: string | null;
  droidVolume: string | null;
  droidObject: string | null;
  droidBirthVolume: string | null;
  droidBirthObject: string | null;
}

export interface LnkPropertyStoreValueBlob {
  length: number;
}

export type LnkPropertyScalar =
  | string
  | number
  | bigint
  | boolean
  | LnkPropertyStoreValueBlob
  | null;

export type LnkPropertyValue = LnkPropertyScalar | LnkPropertyScalar[];

export interface LnkProperty {
  id: number;
  name: string | null;
  type: number | null;
  typeName: string | null;
  value: LnkPropertyValue;
  truncated: boolean;
  valueSize: number;
  isVector: boolean;
}

export interface LnkPropertyStorage {
  formatId: string | null;
  size: number;
  magic: string;
  truncated: boolean;
  properties: LnkProperty[];
}

export interface LnkPropertyStoreData {
  storages: LnkPropertyStorage[];
}

export interface LnkVistaIdListData {
  items: LnkIdListItem[];
  terminatorPresent: boolean;
}

export interface LnkExtraDataBlockBase {
  size: number;
  signature: number;
  name: string | null;
  truncated: boolean;
}

export type LnkEnvironmentBlock = LnkExtraDataBlockBase & {
  signature: 0xa0000001 | 0xa0000006 | 0xa0000007;
  parsed: LnkEnvironmentStrings | null;
};

export type LnkConsoleCodePageBlock = LnkExtraDataBlockBase & {
  signature: 0xa0000004;
  parsed: { codePage: number } | null;
};

export type LnkSpecialFolderBlock = LnkExtraDataBlockBase & {
  signature: 0xa0000005;
  parsed: LnkSpecialFolderData | null;
};

export type LnkKnownFolderBlock = LnkExtraDataBlockBase & {
  signature: 0xa000000b;
  parsed: LnkKnownFolderData | null;
};

export type LnkTrackerBlock = LnkExtraDataBlockBase & {
  signature: 0xa0000003;
  parsed: LnkTrackerData | null;
};

export type LnkPropertyStoreBlock = LnkExtraDataBlockBase & {
  signature: 0xa0000009;
  parsed: LnkPropertyStoreData | null;
};

export type LnkVistaIdListBlock = LnkExtraDataBlockBase & {
  signature: 0xa000000c;
  parsed: LnkVistaIdListData | null;
};

export type LnkExtraDataBlock =
  | LnkEnvironmentBlock
  | LnkConsoleCodePageBlock
  | LnkSpecialFolderBlock
  | LnkKnownFolderBlock
  | LnkTrackerBlock
  | LnkPropertyStoreBlock
  | LnkVistaIdListBlock
  | (LnkExtraDataBlockBase & { parsed: unknown });

export interface LnkExtraData {
  blocks: LnkExtraDataBlock[];
  endOffset: number;
}

export interface LnkParseResult {
  header: LnkHeader;
  idList: LnkIdList | null;
  linkInfo: LnkLinkInfo | null;
  stringData: LnkStringData;
  extraData: LnkExtraData;
  warnings: string[];
  linkInfoPath: string | null;
}
