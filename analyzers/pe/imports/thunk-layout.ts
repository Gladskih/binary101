// PE32 and PE32+ use 32-bit and 64-bit entries in both lookup and address tables.
// https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#import-lookup-table
export const IMAGE_THUNK_DATA32_SIZE = Uint32Array.BYTES_PER_ELEMENT;
export const IMAGE_THUNK_DATA64_SIZE = BigUint64Array.BYTES_PER_ELEMENT;
