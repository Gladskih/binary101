"use strict";

export type GoRuntimeLayout = "go1.16-1.17" | "go1.18-1.19" | "go1.20+";

export interface GoRuntimeAddressSpace {
  pointerSize: 4 | 8;
  readMapped: (address: bigint, size: number) => Promise<Uint8Array | null>;
  isMappedRange: (address: bigint, size: number) => boolean;
  isExecutableRange: (start: bigint, end: bigint) => boolean;
}

export interface GoRuntimeFunction {
  name: string;
  start: bigint;
  end: bigint;
}

export interface GoRuntimeMetadata {
  layout: GoRuntimeLayout;
  pointerSize: 4 | 8;
  pcHeaderAddress: bigint;
  moduleDataAddress: bigint;
  fileCount: number;
  textRange: { start: bigint; end: bigint };
  functions: GoRuntimeFunction[];
}
