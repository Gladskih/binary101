"use strict";

import type { MsvcRttiImage } from "./image.js";
import {
  BASE_CLASS_ATTRIBUTES,
  BASE_CLASS_DESCRIPTOR_SIZE,
  BASE_CLASS_KNOWN_ATTRIBUTES,
  CLASS_HIERARCHY_DESCRIPTOR_REVISION,
  CLASS_HIERARCHY_DESCRIPTOR_SIZE,
  CLASS_HIERARCHY_KNOWN_ATTRIBUTES,
  COMPLETE_OBJECT_LOCATOR_REVISION_1,
  COMPLETE_OBJECT_LOCATOR_SIZE,
  MAX_BASE_CLASS_DESCRIPTORS
} from "./layout.js";
import type { MsvcRttiPmd } from "./types.js";

export interface ParsedCompleteObjectLocator {
  offset: number;
  cdOffset: number;
  typeDescriptorRva: number;
  classHierarchyDescriptorRva: number;
}

export interface ParsedClassHierarchyDescriptor {
  attributes: number;
  numBaseClasses: number;
  baseClassArrayRva: number;
}

export interface ParsedBaseClassDescriptor {
  typeDescriptorRva: number;
  numContainedBases: number;
  pmd: MsvcRttiPmd;
  attributes: number;
  classHierarchyDescriptorRva: number;
}

export const parseCompleteObjectLocator = async (
  image: MsvcRttiImage,
  rva: number
): Promise<ParsedCompleteObjectLocator | null> => {
  const view = await image.readData(rva, COMPLETE_OBJECT_LOCATOR_SIZE, Uint32Array.BYTES_PER_ELEMENT);
  if (!view || view.getUint32(0, true) !== COMPLETE_OBJECT_LOCATOR_REVISION_1) return null;
  if (view.getUint32(20, true) !== rva) return null;
  const typeDescriptorRva = view.getUint32(12, true);
  const classHierarchyDescriptorRva = view.getUint32(16, true);
  if (!typeDescriptorRva || !classHierarchyDescriptorRva) return null;
  return {
    offset: view.getUint32(4, true),
    cdOffset: view.getUint32(8, true),
    typeDescriptorRva,
    classHierarchyDescriptorRva
  };
};

export const parseClassHierarchyDescriptor = async (
  image: MsvcRttiImage,
  rva: number
): Promise<ParsedClassHierarchyDescriptor | null> => {
  const view = await image.readData(rva, CLASS_HIERARCHY_DESCRIPTOR_SIZE, Uint32Array.BYTES_PER_ELEMENT);
  if (!view || view.getUint32(0, true) !== CLASS_HIERARCHY_DESCRIPTOR_REVISION) return null;
  const attributes = view.getUint32(4, true);
  const numBaseClasses = view.getUint32(8, true);
  const baseClassArrayRva = view.getUint32(12, true);
  if ((attributes & ~CLASS_HIERARCHY_KNOWN_ATTRIBUTES) !== 0) return null;
  if (!numBaseClasses || numBaseClasses > MAX_BASE_CLASS_DESCRIPTORS || !baseClassArrayRva) return null;
  return { attributes, numBaseClasses, baseClassArrayRva };
};

export const parseBaseClassDescriptor = async (
  image: MsvcRttiImage,
  rva: number
): Promise<ParsedBaseClassDescriptor | null> => {
  const view = await image.readData(rva, BASE_CLASS_DESCRIPTOR_SIZE, Uint32Array.BYTES_PER_ELEMENT);
  if (!view) return null;
  const attributes = view.getUint32(20, true);
  const typeDescriptorRva = view.getUint32(0, true);
  const classHierarchyDescriptorRva = view.getUint32(24, true);
  if ((attributes & ~BASE_CLASS_KNOWN_ATTRIBUTES) !== 0) return null;
  if ((attributes & BASE_CLASS_ATTRIBUTES.hasClassHierarchyDescriptor) === 0) return null;
  if (!typeDescriptorRva || !classHierarchyDescriptorRva) return null;
  return {
    typeDescriptorRva,
    numContainedBases: view.getUint32(4, true),
    pmd: {
      mdisp: view.getInt32(8, true),
      pdisp: view.getInt32(12, true),
      vdisp: view.getInt32(16, true)
    },
    attributes,
    classHierarchyDescriptorRva
  };
};

