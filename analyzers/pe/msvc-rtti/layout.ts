"use strict";

// LLVM MicrosoftCXXABI.cpp and the MSVC 14.51 rttidata.h force-include define
// the modern Win64 image-relative RTTI records used here.
// https://github.com/llvm/llvm-project/blob/main/clang/lib/CodeGen/MicrosoftCXXABI.cpp
export const MSVC_RTTI_LAYOUT = "microsoft-cxx-amd64-image-relative-rtti-rev1" as const;

export const COMPLETE_OBJECT_LOCATOR_SIZE = 24;
export const TYPE_DESCRIPTOR_FIXED_SIZE = 16;
export const CLASS_HIERARCHY_DESCRIPTOR_SIZE = 16;
export const BASE_CLASS_DESCRIPTOR_SIZE = 28;
export const IMAGE_RELATIVE_POINTER_SIZE = 4;
export const IMAGE_POINTER_SIZE = 8;

export const COMPLETE_OBJECT_LOCATOR_REVISION_1 = 1;
export const CLASS_HIERARCHY_DESCRIPTOR_REVISION = 0;
export const MAX_TYPE_DESCRIPTOR_NAME_BYTES = 1024;
export const MAX_BASE_CLASS_DESCRIPTORS = 4096;
export const MAX_HIERARCHY_DEPTH = 64;
export const MAX_VFTABLE_SLOTS = 4096;

// MSVC rttidata.h: CHD_MULTINH, CHD_VIRTINH, CHD_AMBIGUOUS.
export const CLASS_HIERARCHY_ATTRIBUTES = {
  multipleInheritance: 0x0000_0001,
  virtualInheritance: 0x0000_0002,
  ambiguous: 0x0000_0004
} as const;

export const CLASS_HIERARCHY_KNOWN_ATTRIBUTES =
  CLASS_HIERARCHY_ATTRIBUTES.multipleInheritance |
  CLASS_HIERARCHY_ATTRIBUTES.virtualInheritance |
  CLASS_HIERARCHY_ATTRIBUTES.ambiguous;

// MSVC rttidata.h: BCD_NOTVISIBLE through BCD_HASPCHD.
export const BASE_CLASS_ATTRIBUTES = {
  notVisible: 0x0000_0001,
  ambiguous: 0x0000_0002,
  privateOrProtectedBase: 0x0000_0004,
  privateOrProtectedInCompleteObject: 0x0000_0008,
  virtualBaseOfCompleteObject: 0x0000_0010,
  nonPolymorphic: 0x0000_0020,
  hasClassHierarchyDescriptor: 0x0000_0040
} as const;

export const BASE_CLASS_KNOWN_ATTRIBUTES =
  BASE_CLASS_ATTRIBUTES.notVisible |
  BASE_CLASS_ATTRIBUTES.ambiguous |
  BASE_CLASS_ATTRIBUTES.privateOrProtectedBase |
  BASE_CLASS_ATTRIBUTES.privateOrProtectedInCompleteObject |
  BASE_CLASS_ATTRIBUTES.virtualBaseOfCompleteObject |
  BASE_CLASS_ATTRIBUTES.nonPolymorphic |
  BASE_CLASS_ATTRIBUTES.hasClassHierarchyDescriptor;
