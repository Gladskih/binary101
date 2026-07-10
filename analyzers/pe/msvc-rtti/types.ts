"use strict";

import type { MSVC_RTTI_LAYOUT } from "./layout.js";

export interface MsvcRttiTypeDescriptor {
  rva: number;
  decoratedName: string;
}

export interface MsvcRttiPmd {
  mdisp: number;
  pdisp: number;
  vdisp: number;
}

export interface MsvcRttiBaseClass {
  descriptorRva: number;
  typeDescriptorRva: number;
  numContainedBases: number;
  pmd: MsvcRttiPmd;
  attributes: number;
  classHierarchyDescriptorRva: number;
  children: MsvcRttiBaseClass[];
}

export interface MsvcRttiClassHierarchy {
  rva: number;
  attributes: number;
  root: MsvcRttiBaseClass;
}

export interface MsvcRttiCompleteObjectLocator {
  rva: number;
  offset: number;
  cdOffset: number;
  typeDescriptorRva: number;
  classHierarchyDescriptorRva: number;
}

export interface MsvcRttiVftable {
  rva: number;
  locatorSlotRva: number;
  completeObjectLocatorRva: number;
  functionTargetRvas: number[];
}

export interface MsvcRttiAnalysis {
  layout: typeof MSVC_RTTI_LAYOUT;
  types: MsvcRttiTypeDescriptor[];
  classHierarchies: MsvcRttiClassHierarchy[];
  completeObjectLocators: MsvcRttiCompleteObjectLocator[];
  vftables: MsvcRttiVftable[];
}

