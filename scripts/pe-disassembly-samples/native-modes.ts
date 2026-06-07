"use strict";

export interface CompilerMode {
  args: string[];
  id: string;
  label: string;
  runtimeLinkage?: string;
}

export const releaseModes: readonly CompilerMode[] = [
  { id: "o0", label: "O0", args: ["-O0"] },
  { id: "o2", label: "O2", args: ["-O2"] },
  { id: "os", label: "Os", args: ["-Os"] }
];

export const cpuModes: readonly CompilerMode[] = [
  {
    id: "o2-march-x86-64-v2",
    label: "O2 -march=x86-64-v2",
    args: ["-O2", "-march=x86-64-v2"]
  },
  {
    id: "o2-march-x86-64-v3",
    label: "O2 -march=x86-64-v3",
    args: ["-O2", "-march=x86-64-v3"]
  },
  { id: "o2-mtune-znver5", label: "O2 -mtune=znver5", args: ["-O2", "-mtune=znver5"] },
  { id: "o2-march-znver5", label: "O2 -march=znver5", args: ["-O2", "-march=znver5"] }
];

export const zigCpuModes: readonly CompilerMode[] = [
  {
    id: "o2-march-x86-64-v2",
    label: "O2 -march=x86_64_v2",
    args: ["-O2", "-march=x86_64_v2"]
  },
  {
    id: "o2-march-x86-64-v3",
    label: "O2 -march=x86_64_v3",
    args: ["-O2", "-march=x86_64_v3"]
  },
  { id: "o2-mtune-znver5", label: "O2 -mtune=znver5", args: ["-O2", "-mtune=znver5"] },
  { id: "o2-march-znver5", label: "O2 -march=znver5", args: ["-O2", "-march=znver5"] }
];

export const ltoMode: CompilerMode = {
  id: "o2-flto",
  label: "O2 -flto",
  args: ["-O2", "-flto"]
};

export const msvcRuntimeModes: readonly CompilerMode[] = [
  { id: "od-md", label: "Od /MD", args: ["/Od", "/MD"], runtimeLinkage: "DLL MSVC CRT" },
  { id: "o2-md", label: "O2 /MD", args: ["/O2", "/MD"], runtimeLinkage: "DLL MSVC CRT" },
  { id: "o2-mt", label: "O2 /MT", args: ["/O2", "/MT"], runtimeLinkage: "static MSVC CRT" }
];

export const msvcExtraModes: readonly CompilerMode[] = [
  {
    id: "o2-md-ltcg",
    label: "O2 /MD /GL /LTCG",
    args: ["/O2", "/MD", "/GL", "/link", "/LTCG"],
    runtimeLinkage: "DLL MSVC CRT"
  },
  {
    id: "o2-md-arch-avx2",
    label: "O2 /MD /arch:AVX2",
    args: ["/O2", "/MD", "/arch:AVX2"],
    runtimeLinkage: "DLL MSVC CRT"
  },
  {
    id: "o2-md-arch-avx512",
    label: "O2 /MD /arch:AVX512",
    args: ["/O2", "/MD", "/arch:AVX512"],
    runtimeLinkage: "DLL MSVC CRT"
  }
];

export const clangClExtraModes: readonly CompilerMode[] = [
  {
    id: "o2-md-flto",
    label: "O2 /MD -flto",
    args: ["/O2", "/MD", "-flto"],
    runtimeLinkage: "DLL MSVC CRT"
  },
  {
    id: "o2-md-march-x86-64-v2",
    label: "O2 /MD -march=x86-64-v2",
    args: ["/O2", "/MD", "-march=x86-64-v2"],
    runtimeLinkage: "DLL MSVC CRT"
  },
  {
    id: "o2-md-march-x86-64-v3",
    label: "O2 /MD -march=x86-64-v3",
    args: ["/O2", "/MD", "-march=x86-64-v3"],
    runtimeLinkage: "DLL MSVC CRT"
  },
  {
    id: "o2-md-mtune-znver5",
    label: "O2 /MD -mtune=znver5",
    args: ["/O2", "/MD", "-mtune=znver5"],
    runtimeLinkage: "DLL MSVC CRT"
  },
  {
    id: "o2-md-march-znver5",
    label: "O2 /MD -march=znver5",
    args: ["/O2", "/MD", "-march=znver5"],
    runtimeLinkage: "DLL MSVC CRT"
  }
];
