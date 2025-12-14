export const KNOWN_CPUID_FEATURES: readonly string[] = [
  "X64",
  "SSE",
  "SSE2",
  "SSE3",
  "SSSE3",
  "SSE4_1",
  "SSE4_2",
  "AVX",
  "AVX2",
  "FMA",
  "BMI1",
  "BMI2",
  "AES",
  "PCLMULQDQ",
  "POPCNT",
  "LZCNT",
  "SHA",
  "AVX512F",
  "AVX512VL",
  "AVX512BW",
  "AVX512DQ",
  "AVX512CD",
  "AVX512_VBMI",
  "AVX512_VBMI2",
  "AVX512_VNNI",
  "AVX512_BITALG",
  "AVX512_VPOPCNTDQ"
];

export const formatCpuidLabel = (name: string): string => {
  if (name === "X64") return "x86-64";
  if (name.startsWith("AVX512_")) return `AVX-512 ${name.slice("AVX512_".length).replaceAll("_", " ")}`;
  if (name.startsWith("AVX10_")) return `AVX10 ${name.slice("AVX10_".length).replaceAll("_", " ")}`;
  if (/^SSE4_[12]$/.test(name)) return name.replace("_", ".");
  return name;
};

const CPUID_DESCRIPTIONS: Record<string, string> = {
  X64: "x86-64 long mode (64-bit registers and addressing).",
  SSE: "Streaming SIMD Extensions (128-bit SIMD instructions).",
  SSE2: "SSE2 SIMD (128-bit integer + double-precision); baseline on x86-64.",
  SSE3: "SSE3 extensions (mostly SIMD horizontal/complex ops).",
  SSSE3: "Supplemental SSE3 (byte-shuffle and other SIMD extensions).",
  SSE4_1: "SSE4.1 SIMD extensions (dot products, blends, etc.).",
  SSE4_2: "SSE4.2 SIMD extensions (string/CRC-related instructions).",
  AVX: "Advanced Vector Extensions (VEX encoding, 256-bit YMM registers).",
  AVX2: "AVX2 integer 256-bit SIMD extensions (incl. gathers).",
  FMA: "FMA3 fused multiply-add (floating point).",
  BMI1: "Bit Manipulation Instructions 1 (e.g., ANDN, BEXTR).",
  BMI2: "Bit Manipulation Instructions 2 (e.g., MULX, PDEP/PEXT).",
  AES: "AES-NI crypto instructions (AES rounds).",
  PCLMULQDQ: "Carry-less multiply (GF(2) multiply; used in GCM/CRC).",
  POPCNT: "Population count instruction.",
  LZCNT: "Leading zero count (ABM/LZCNT).",
  SHA: "SHA extensions (SHA1/SHA256 rounds).",
  AVX512F: "AVX-512 Foundation (512-bit ZMM registers).",
  AVX512VL: "AVX-512 Vector Length extensions (128/256-bit forms).",
  AVX512BW: "AVX-512 Byte/Word instructions.",
  AVX512DQ: "AVX-512 Doubleword/Quadword instructions.",
  AVX512CD: "AVX-512 Conflict Detection (CD).",
  AVX512_VBMI: "AVX-512 VBMI (Vector Byte Manipulation Instructions).",
  AVX512_VBMI2: "AVX-512 VBMI2 (additional byte manipulation).",
  AVX512_VNNI: "AVX-512 VNNI (integer dot-product for ML).",
  AVX512_BITALG: "AVX-512 BITALG (bit algorithms).",
  AVX512_VPOPCNTDQ: "AVX-512 VPOPCNTDQ (vector popcount)."
};

export const describeCpuidFeature = (name: string): string => {
  const known = CPUID_DESCRIPTIONS[name];
  if (known) return known;
  if (name.startsWith("AVX512_")) return "AVX-512 extension (subset; typically requires AVX512F).";
  if (name.startsWith("AVX10_")) return "AVX10 extension (newer AVX family).";
  if (name.startsWith("AVX")) return "Advanced Vector Extensions family feature.";
  if (name.startsWith("SSE")) return "SSE family SIMD extension.";
  if (name.endsWith("_ONLY")) return "CPU-specific/legacy-only instruction variant.";
  return "CPUID feature flag required by at least one decoded instruction.";
};
