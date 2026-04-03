"use strict";

import { mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import type { VariantSpec } from "./rustPeMatrix-model.js";

const RUST_CONSOLE_SOURCE = `fn main() {
    println!("Hello, world!");
}
`;

const RUST_WINDOWS_SOURCE = `#![windows_subsystem = "windows"]

fn main() {
    let _ = "Hello, world!";
}
`;

const coreOptLevels = ["0", "1", "3", "s", "z"] as const;
const coreDebugLevels = ["0", "2"] as const;
const corePanicStrategies = ["unwind", "abort"] as const;
const coreStripModes = ["none", "symbols"] as const;
const coreTargetCpus = ["generic", "x86-64", "x86-64-v2", "x86-64-v3", "native"] as const;

export const writeSourceFiles = async (sourceRoot: string): Promise<Record<string, string>> => {
  await mkdir(sourceRoot, { recursive: true });
  const consolePath = join(sourceRoot, "hello.rs");
  const windowsPath = join(sourceRoot, "hello-windows.rs");
  await writeFile(consolePath, RUST_CONSOLE_SOURCE, "utf8");
  await writeFile(windowsPath, RUST_WINDOWS_SOURCE, "utf8");
  return {
    "hello.rs": consolePath,
    "hello-windows.rs": windowsPath
  };
};

export const buildCoreVariantSpecs = (hostTarget: string): VariantSpec[] => {
  const variants: VariantSpec[] = [];
  for (const optLevel of coreOptLevels) {
    for (const debugLevel of coreDebugLevels) {
      for (const panicStrategy of corePanicStrategies) {
        for (const stripMode of coreStripModes) {
          for (const targetCpu of coreTargetCpus) {
            variants.push({
              id: `core-opt${optLevel}-dbg${debugLevel}-panic${panicStrategy}-strip${stripMode}-cpu${targetCpu}`,
              label: `opt=${optLevel}, debug=${debugLevel}, panic=${panicStrategy}, strip=${stripMode}, cpu=${targetCpu}`,
              sourceFile: "hello.rs",
              target: hostTarget,
              rustcArgs: [
                "-C", `opt-level=${optLevel}`,
                "-C", `debuginfo=${debugLevel}`,
                "-C", `panic=${panicStrategy}`,
                "-C", `strip=${stripMode}`,
                "-C", `target-cpu=${targetCpu}`
              ]
            });
          }
        }
      }
    }
  }
  return variants;
};

export const buildExperimentalVariantSpecs = (hostTarget: string): VariantSpec[] => [
  {
    id: "exp-lto-thin",
    label: "thin LTO release",
    sourceFile: "hello.rs",
    target: hostTarget,
    rustcArgs: ["-C", "opt-level=3", "-C", "debuginfo=0", "-C", "lto=thin", "-C", "codegen-units=1"]
  },
  {
    id: "exp-lto-fat",
    label: "fat LTO release",
    sourceFile: "hello.rs",
    target: hostTarget,
    rustcArgs: ["-C", "opt-level=3", "-C", "debuginfo=0", "-C", "lto=fat", "-C", "codegen-units=1"]
  },
  {
    id: "exp-strip-debuginfo",
    label: "strip debuginfo only",
    sourceFile: "hello.rs",
    target: hostTarget,
    rustcArgs: ["-C", "opt-level=3", "-C", "debuginfo=0", "-C", "strip=debuginfo"]
  },
  {
    id: "exp-force-frame-pointers",
    label: "force frame pointers",
    sourceFile: "hello.rs",
    target: hostTarget,
    rustcArgs: ["-C", "opt-level=3", "-C", "debuginfo=0", "-C", "force-frame-pointers=yes"]
  },
  {
    id: "exp-embed-bitcode",
    label: "embed LLVM bitcode",
    sourceFile: "hello.rs",
    target: hostTarget,
    rustcArgs: ["-C", "opt-level=3", "-C", "debuginfo=0", "-C", "embed-bitcode=yes"]
  },
  {
    id: "exp-subsystem-windows",
    label: "windows subsystem",
    sourceFile: "hello-windows.rs",
    target: hostTarget,
    rustcArgs: ["-C", "opt-level=3", "-C", "debuginfo=0"]
  },
  {
    id: "exp-link-base",
    label: "non-default image base",
    sourceFile: "hello.rs",
    target: hostTarget,
    rustcArgs: ["-C", "opt-level=3", "-C", "debuginfo=0", "-C", "link-arg=-Wl,/base:0x180000000"]
  },
  {
    id: "exp-link-align",
    label: "section alignment 8192",
    sourceFile: "hello.rs",
    target: hostTarget,
    rustcArgs: ["-C", "opt-level=3", "-C", "debuginfo=0", "-C", "link-arg=-Wl,/align:8192"]
  },
  {
    id: "exp-link-filealign",
    label: "file alignment 4096",
    sourceFile: "hello.rs",
    target: hostTarget,
    rustcArgs: ["-C", "opt-level=3", "-C", "debuginfo=0", "-C", "link-arg=-Wl,/filealign:4096"]
  },
  {
    id: "exp-link-stack-reserve",
    label: "stack reserve 4 MiB",
    sourceFile: "hello.rs",
    target: hostTarget,
    rustcArgs: ["-C", "opt-level=3", "-C", "debuginfo=0", "-C", "link-arg=-Wl,/stack:0x400000"]
  },
  {
    id: "exp-link-heap-reserve",
    label: "heap reserve 4 MiB",
    sourceFile: "hello.rs",
    target: hostTarget,
    rustcArgs: ["-C", "opt-level=3", "-C", "debuginfo=0", "-C", "link-arg=-Wl,/heap:0x400000"]
  },
  {
    id: "cross-i686-gnullvm",
    label: "cross-target i686-pc-windows-gnullvm",
    sourceFile: "hello.rs",
    target: "i686-pc-windows-gnullvm",
    rustcArgs: ["-C", "opt-level=3", "-C", "debuginfo=0"]
  },
  {
    id: "cross-aarch64-gnullvm",
    label: "cross-target aarch64-pc-windows-gnullvm",
    sourceFile: "hello.rs",
    target: "aarch64-pc-windows-gnullvm",
    rustcArgs: ["-C", "opt-level=3", "-C", "debuginfo=0"]
  },
  {
    id: "cross-i686-msvc",
    label: "cross-target i686-pc-windows-msvc",
    sourceFile: "hello.rs",
    target: "i686-pc-windows-msvc",
    rustcArgs: ["-C", "opt-level=3", "-C", "debuginfo=0"]
  },
  {
    id: "cross-aarch64-msvc",
    label: "cross-target aarch64-pc-windows-msvc",
    sourceFile: "hello.rs",
    target: "aarch64-pc-windows-msvc",
    rustcArgs: ["-C", "opt-level=3", "-C", "debuginfo=0"]
  },
  {
    id: "cross-thumbv7a-msvc",
    label: "cross-target thumbv7a-pc-windows-msvc",
    sourceFile: "hello.rs",
    target: "thumbv7a-pc-windows-msvc",
    rustcArgs: ["-C", "opt-level=3", "-C", "debuginfo=0"]
  }
];
