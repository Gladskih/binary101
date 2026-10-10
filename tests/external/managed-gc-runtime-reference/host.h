#include <algorithm>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>
// Host declarations only; this adapter implements no GC decoding logic.
#define TARGET_AMD64
#define TARGET_64BIT
#define FEATURE_NATIVEAOT
#define GCINFODECODER_NO_EE
#ifdef GC_REFERENCE_LEGACY
#define DECODE_OLD_FORMATS
#endif

#define __forceinline inline
#define _ASSERTE(x) ((void)0)
#define NOINLINE __attribute__((noinline))
#define SUPPORTS_DAC
#define ArrayDPTR(type) type *
#define GC_CALL_INTERIOR 1
#define GC_CALL_PINNED 2
#define IS_ALIGNED(value, alignment) (((uintptr_t)(value) % (alignment)) == 0)
using PTR_VOID = void *;
using PTR_size_t = size_t *;
using PTR_uintptr_t = uintptr_t *;
using TADDR = uintptr_t;
using BOOL = bool;
constexpr bool TRUE = true, FALSE = false;
template <class T, class U> T dac_cast(U value) { return (T)value; }
struct RegDisplay {
  uintptr_t *registerPointers[15];
  uintptr_t SP;
};
// NativeAOT's contiguous register-pointer array omits RSP.
#define pRax registerPointers[0]
using PREGDISPLAY = RegDisplay *;
using GCEnumCallback = void (*)(void *, void **, uint32_t);
