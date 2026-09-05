"use strict";

export type PeAppHostBundleLocation = {
  offset: bigint;
  size: bigint;
};

export type PeAppHostBundleHeader = {
  majorVersion: number;
  minorVersion: number;
  embeddedFileCount: number;
  bundleId: string | null;
  depsJson?: PeAppHostBundleLocation;
  runtimeConfigJson?: PeAppHostBundleLocation;
  flags?: bigint;
};

export type PeAppHostLocator = {
  rva: number;
  bundleHeaderOffset: bigint | null;
  bundleHeader?: PeAppHostBundleHeader;
};

export type PeAppHostBinding = {
  rva: number;
  kind: "managed-assembly" | "unbound-placeholder";
  value: string;
};

export type PeAppHostAnalysis = {
  locators: PeAppHostLocator[];
  bindings: PeAppHostBinding[];
  issues: string[];
};
