// MSVC 14.51 include/ehdata_forceinclude.h: TypeDescriptor contains two native pointers,
// followed by the stored decorated name. EH and RTTI use this same ABI structure.
// https://github.com/llvm/llvm-project/blob/main/clang/lib/CodeGen/MicrosoftCXXABI.cpp
export const TYPE_DESCRIPTOR_POINTER_FIELDS = 2;
export const TYPE_DESCRIPTOR_FIXED_SIZE = TYPE_DESCRIPTOR_POINTER_FIELDS * BigUint64Array.BYTES_PER_ELEMENT;

// Existing bounded RTTI name policy, shared with EH. This is an analysis resource limit,
// not an ABI limit: longer names stay unresolved rather than being truncated and reported.
export const MAX_TYPE_DESCRIPTOR_NAME_BYTES = 1024;
