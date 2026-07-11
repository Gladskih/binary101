"use strict";

export type PeLoadConfigPointerList = {
  tableRva: number;
  values: bigint[];
  terminated: boolean;
};

export type PeLoadConfigPointerValue = {
  rva: number;
  value: bigint;
};

export type PeChpeCodeMapEntry = {
  startRva: number;
  length: number;
  kind: "ARM64" | "ARM64EC" | "AMD64" | "X86" | "UNKNOWN";
};

export type PeChpeEntryPointRange = {
  startRva: number;
  endRva: number;
  entryPointRva: number;
};

export type PeChpeRedirection = {
  sourceRva: number;
  destinationRva: number;
};

export type PeArm64RuntimeFunctionEntry = { beginRva: number } & (
  { unwindKind: "exception"; exceptionInformationRva: number } |
  {
    unwindKind: "packed" | "packed-fragment";
    functionLengthBytes: number;
    savedFpRegisterField: number;
    savedIntegerRegisterCount: number;
    homesIntegerParameters: boolean;
    chainReturn: "unchained" | "saves-lr" | "chained-pac" | "chained";
    frameSizeBytes: number;
  } |
  { unwindKind: "chained"; targetPdataRva: number }
);

type PeChpeMetadataBase = {
  rva: number;
  version: number;
  codeMapRva: number;
  codeMapCount: number;
  codeMap: PeChpeCodeMapEntry[];
};

export type PeChpeArm64EcMetadata = PeChpeMetadataBase & {
  kind: "arm64ec";
  codeRangesToEntryPointsRva: number;
  redirectionMetadataRva: number;
  osArm64xDispatchCallNoRedirectRva: number;
  osArm64xDispatchRetRva: number;
  osArm64xDispatchCallRva: number;
  osArm64xDispatchIcallRva: number;
  osArm64xDispatchIcallCfgRva: number;
  alternateEntryPointRva: number;
  auxiliaryIatRva: number;
  codeRangesToEntryPointsCount: number;
  redirectionMetadataCount: number;
  getX64InformationFunctionPointerRva: number;
  setX64InformationFunctionPointerRva: number;
  extraRfeTableRva: number;
  extraRfeTableSize: number;
  osArm64xDispatchFptrRva: number;
  auxiliaryIatCopyRva: number;
  extraRfeEntries: PeArm64RuntimeFunctionEntry[];
  auxiliaryDelayloadIatRva?: number;
  auxiliaryDelayloadIatCopyRva?: number;
  hybridImageInfoBitfield?: number;
  entryPointRanges: PeChpeEntryPointRange[];
  redirections: PeChpeRedirection[];
};

export type PeChpeX86Metadata = PeChpeMetadataBase & {
  kind: "x86";
  wowA64ExceptionHandlerRva: number;
  wowA64DispatchCallRva: number;
  wowA64DispatchIndirectCallRva: number;
  wowA64DispatchIndirectCallCfgRva: number;
  wowA64DispatchRetRva: number;
  wowA64DispatchRetLeafRva: number;
  wowA64DispatchJumpRva: number;
  compilerIatRva?: number;
  wowA64RdtscRva?: number;
};

export type PeChpeMetadata = PeChpeArm64EcMetadata | PeChpeX86Metadata;

export type PeEnclaveImport = {
  matchType: "NONE" | "UNIQUE_ID" | "AUTHOR_ID" | "FAMILY_ID" | "IMAGE_ID" | "UNKNOWN";
  minimumSecurityVersion: number;
  uniqueOrAuthorId: number[];
  familyId: number[];
  imageId: number[];
  nameRva: number;
  name?: string;
  reserved: number;
};

export type PeEnclaveConfiguration = {
  rva: number;
  size: number;
  minimumRequiredConfigSize: number;
  policyFlags: number;
  numberOfImports: number;
  importListRva: number;
  importEntrySize: number;
  familyId: number[];
  imageId: number[];
  imageVersion: number;
  securityVersion: number;
  enclaveSize: bigint;
  numberOfThreads: number;
  enclaveFlags?: number;
  imports: PeEnclaveImport[];
};

export type PeHotPatchBase = {
  offset: number;
  sequenceNumber: number;
  flags: number;
  originalTimeDateStamp: number;
  originalCheckSum: number;
  codeIntegrityInfoOffset: number;
  codeIntegritySize: number;
  patchTableOffset: number;
  bufferOffset?: number;
  codeIntegrityHashes?: {
    sha256: number[];
    sha1: number[];
  };
};

export type PeHotPatchInfo = {
  rva: number;
  version: number;
  size: number;
  sequenceNumber: number;
  baseImageListOffset: number;
  baseImageCount: number;
  bufferOffset?: number;
  extraPatchSize?: number;
  minSequenceNumber?: number;
  flags?: number;
  baseImages: PeHotPatchBase[];
};

export type PeVolatileMetadataRange = {
  rva: number;
  size: number;
};

export type PeVolatileMetadata = {
  rva: number;
  size: number;
  minimumVersion: number;
  maximumVersion: number;
  accessTableRva: number;
  accessTableSize: number;
  infoRangeTableRva: number;
  infoRangeTableSize: number;
  accessRvas: number[];
  infoRanges: PeVolatileMetadataRange[];
};

export type PeLoadConfigOpaqueReference = {
  name: "EditList" | "UmaFunctionPointers";
  pointerVa: bigint;
  reason: string;
};

export type PeLoadConfigReferences = {
  lockPrefixTable?: PeLoadConfigPointerList;
  securityCookie?: PeLoadConfigPointerValue;
  pointerSlots?: Partial<Record<
    "GuardCFCheckFunctionPointer" |
    "GuardCFDispatchFunctionPointer" |
    "GuardRFFailureRoutineFunctionPointer" |
    "GuardRFVerifyStackPointerFunctionPointer" |
    "GuardXFGCheckFunctionPointer" |
    "GuardXFGDispatchFunctionPointer" |
    "GuardXFGTableDispatchFunctionPointer" |
    "CastGuardOsDeterminedFailureMode" |
    "GuardMemcpyFunctionPointer",
    PeLoadConfigPointerValue
  >>;
  chpeMetadata?: PeChpeMetadata;
  enclaveConfiguration?: PeEnclaveConfiguration;
  hotPatch?: PeHotPatchInfo;
  volatileMetadata?: PeVolatileMetadata;
  opaque?: PeLoadConfigOpaqueReference[];
  warnings?: string[];
  notes?: string[];
};
