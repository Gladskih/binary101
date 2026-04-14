"use strict";

export type PeIatDirectoryRelation =
  | "covered"
  | "outside-directory"
  | "missing-directory"
  | "missing-table-rva";

export type PeImportBindingRelation =
  | "none"
  | "timestamp-only"
  | "bound-directory-match";

export type PeDeclaredIatRelation =
  | "declared-absent"
  | "exact-match"
  | "declared-covers-inferred"
  | "declared-misses-inferred";

export interface PeImportLinkingFinding {
  code: string;
  severity: "confirmed" | "info" | "warning";
  message: string;
}

export interface PeLinkedImportDescriptor {
  importIndex: number;
  iatDirectoryRelation: PeIatDirectoryRelation;
  bindingRelation: PeImportBindingRelation;
}

export interface PeLinkedBoundImportDescriptor {
  boundImportIndex: number;
}

export interface PeLinkedDelayImportDescriptor {
  delayImportIndex: number;
  iatDirectoryRelation: PeIatDirectoryRelation;
}

export interface PeInferredEagerIatRange {
  startRva: number;
  endRva: number;
  size: number;
  importIndices: number[];
  descriptorCount: number;
}

export interface PeInferredEagerIat {
  ranges: PeInferredEagerIatRange[];
  aggregateStartRva: number;
  aggregateEndRva: number;
  aggregateSize: number;
  thunkEntrySize: number;
  relationToDeclared: PeDeclaredIatRelation;
}

export interface PeImportLinkingModule {
  moduleKey: string;
  imports: PeLinkedImportDescriptor[];
  boundImports: PeLinkedBoundImportDescriptor[];
  delayImports: PeLinkedDelayImportDescriptor[];
  findings?: PeImportLinkingFinding[];
}

export interface PeImportLinkingResult {
  modules: PeImportLinkingModule[];
  inferredEagerIat: PeInferredEagerIat | null;
  findings?: PeImportLinkingFinding[];
}
