"use strict";

export interface PeClrStreamInfo {
  name: string;
  offset: number;
  size: number;
}

export interface PeClrMeta {
  version?: string;
  verMajor?: number;
  verMinor?: number;
  reserved?: number;
  flags?: number;
  streamCount?: number;
  signature?: number;
  streams: PeClrStreamInfo[];
}

export interface PeClrVTableFixup {
  RVA: number;
  Count: number;
  Type: number;
}

export interface PeClrHeader {
  cb: number;
  MajorRuntimeVersion: number;
  MinorRuntimeVersion: number;
  MetaDataRVA: number;
  MetaDataSize: number;
  Flags: number;
  EntryPointToken: number;
  ResourcesRVA: number;
  ResourcesSize: number;
  StrongNameSignatureRVA: number;
  StrongNameSignatureSize: number;
  CodeManagerTableRVA: number;
  CodeManagerTableSize: number;
  VTableFixupsRVA: number;
  VTableFixupsSize: number;
  ExportAddressTableJumpsRVA: number;
  ExportAddressTableJumpsSize: number;
  ManagedNativeHeaderRVA: number;
  ManagedNativeHeaderSize: number;
  meta?: PeClrMeta;
  vtableFixups?: PeClrVTableFixup[];
  issues?: string[];
}

