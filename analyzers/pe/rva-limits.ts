"use strict";

// Microsoft PE format: section VirtualAddress values and RVAs are 32-bit fields.
// Use 2^32 as the exclusive upper bound so high-RVA spans clamp instead of wrapping to 0.
export const PE_RVA_EXCLUSIVE_LIMIT = 0x1_0000_0000;
