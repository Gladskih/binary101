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

export interface PeImportLinkingModule {
  moduleKey: string;
  imports: PeLinkedImportDescriptor[];
  boundImports: PeLinkedBoundImportDescriptor[];
  delayImports: PeLinkedDelayImportDescriptor[];
  findings?: PeImportLinkingFinding[];
}

export interface PeImportLinkingResult {
  modules: PeImportLinkingModule[];
}
