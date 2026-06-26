"use strict";

import { spawn } from "node:child_process";
import { mkdir, rm, writeFile } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { UCRT_METADATA_CACHE_DIR, UCRT_METADATA_PACKAGES } from "./config.js";
import {
  extractUcrtPackageEntry,
  listUcrtHeaderEntries
} from "./nuget-package.js";

const WORKSPACE_DIR = join(UCRT_METADATA_CACHE_DIR, "workspace");
export const UCRT_INCLUDE_DIR = join(WORKSPACE_DIR, "ucrt");
export const SHARED_INCLUDE_DIR = join(WORKSPACE_DIR, "shared");
export const SHIM_INCLUDE_DIR = join(WORKSPACE_DIR, "shim");

const UCRT_HEADER_SKIP_NAMES = new Set([
  "new.h",
  "safeint.h",
  "safeint_internal.h",
  "stdalign.h",
  "stdnoreturn.h",
  "tchar.h",
  "tgmath.h"
]);

const SHARED_HEADER_NAMES = new Set([
  "concurrencysal.h",
  "sal.h",
  "sdkddkver.h",
  "specstrings.h",
  "specstrings_strict.h",
  "specstrings_undef.h",
  "winapifamily.h"
]);

const normalizedEntryPath = (entryName: string, root: string): string =>
  entryName.slice(root.length + 1);

const writeShimHeaders = async (): Promise<void> => {
  await writeFile(join(SHIM_INCLUDE_DIR, "vcruntime.h"), [
    "#pragma once",
    "#ifndef _MSC_VER",
    "#define _MSC_VER 1940",
    "#endif",
    "#ifndef _M_X64",
    "#define _M_X64 100",
    "#endif",
    "#ifndef _M_AMD64",
    "#define _M_AMD64 100",
    "#endif",
    "#ifndef _WIN64",
    "#define _WIN64 1",
    "#endif",
    "#define _VCRT_COMPILER_PREPROCESSOR 1",
    "#define _CRT_PACKING 8",
    "#define _CRT_BEGIN_C_HEADER __pragma(pack(push, _CRT_PACKING))",
    "#define _CRT_END_C_HEADER __pragma(pack(pop))",
    "#define __CRTDECL __cdecl",
    "#define _VCRTIMP",
    "#define _CRTIMP",
    "#define _VCRT_DEFINED_CRTIMP 1",
    "#define _CRT_DEPRECATE_TEXT(_Text) __declspec(deprecated(_Text))",
    "#define _CRT_INSECURE_DEPRECATE(_Replacement) __declspec(deprecated)",
    "#define _CRT_INSECURE_DEPRECATE_GLOBALS(_Replacement) __declspec(deprecated)",
    "#define _CRT_INSECURE_DEPRECATE_MEMORY(_Replacement) __declspec(deprecated)",
    "#define _CRT_MANAGED_HEAP_DEPRECATE __declspec(deprecated)",
    "#define _CRT_OBSOLETE(_NewItem) __declspec(deprecated)",
    "#define _CRT_NONSTDC_DEPRECATE(_Replacement) __declspec(deprecated)",
    "#define _CRT_SECURE_CPP_NOTHROW",
    "#define _CRT_NOEXCEPT",
    "#define _CONST_RETURN",
    "#define _CRTIMP_ALT",
    "#define _W64",
    "#define _CRT_ALIGN(x) __declspec(align(x))",
    "typedef unsigned __int64 size_t;",
    "typedef __int64 ptrdiff_t;",
    "typedef __int64 intptr_t;",
    "typedef unsigned __int64 uintptr_t;",
    "#ifndef __cplusplus",
    "typedef unsigned short wchar_t;",
    "#endif",
    "typedef char* va_list;",
    "typedef __int64 __time64_t;",
    "typedef long __time32_t;",
    "#include <sal.h>",
    ""
  ].join("\n"));
  await writeFile(join(SHIM_INCLUDE_DIR, "vcruntime_string.h"), [
    "#pragma once",
    "void *memset(void *, int, size_t);",
    "void *memcpy(void *, const void *, size_t);",
    "void *memmove(void *, const void *, size_t);",
    ""
  ].join("\n"));
  await writeFile(join(SHIM_INCLUDE_DIR, "vcruntime_startup.h"), [
    "#pragma once",
    "typedef enum _crt_argv_mode {",
    "  _crt_argv_no_arguments,",
    "  _crt_argv_unexpanded_arguments,",
    "  _crt_argv_expanded_arguments",
    "} _crt_argv_mode;",
    ""
  ].join("\n"));
  await writeFile(join(SHIM_INCLUDE_DIR, "vcruntime_new_debug.h"), "#pragma once\n");
  await writeFile(join(SHIM_INCLUDE_DIR, "intrin.h"), "#pragma once\n");
};

export const extractHeaderWorkspace = async (headerPackageBytes: Uint8Array): Promise<string[]> => {
  await rm(WORKSPACE_DIR, { recursive: true, force: true });
  await mkdir(UCRT_INCLUDE_DIR, { recursive: true });
  await mkdir(SHARED_INCLUDE_DIR, { recursive: true });
  await mkdir(SHIM_INCLUDE_DIR, { recursive: true });
  const includedUcrtHeaders: string[] = [];
  for (const entryName of listUcrtHeaderEntries(headerPackageBytes)) {
    if (entryName.endsWith("/")) continue;
    const isUcrtHeader = entryName.startsWith(`${UCRT_METADATA_PACKAGES.headers.ucrtHeaderRoot}/`);
    const root = isUcrtHeader
      ? UCRT_METADATA_PACKAGES.headers.ucrtHeaderRoot
      : UCRT_METADATA_PACKAGES.headers.sharedHeaderRoot;
    const relative = normalizedEntryPath(entryName, root);
    const fileName = relative.split("/").at(-1) ?? relative;
    if (isUcrtHeader && UCRT_HEADER_SKIP_NAMES.has(fileName)) continue;
    if (!isUcrtHeader && !SHARED_HEADER_NAMES.has(fileName)) continue;
    const target = join(isUcrtHeader ? UCRT_INCLUDE_DIR : SHARED_INCLUDE_DIR, ...relative.split("/"));
    await mkdir(dirname(target), { recursive: true });
    await writeFile(target, extractUcrtPackageEntry(headerPackageBytes, entryName));
    if (isUcrtHeader && fileName.endsWith(".h")) includedUcrtHeaders.push(target);
  }
  await writeShimHeaders();
  return includedUcrtHeaders.sort((left, right) => left.localeCompare(right));
};

const includePath = (path: string): string =>
  resolve(path).replaceAll("\\", "/");

const buildClangInput = (headers: string[]): string => [
  "#define _NO_CRT_STDIO_INLINE 1",
  ...headers.map(header => `#include "${includePath(header)}"`)
].join("\n");

const runProcess = async (
  command: string,
  args: string[],
  input?: string
): Promise<{ stdout: string; stderr: string }> => new Promise((resolveProcess, reject) => {
  const child = spawn(command, args, { stdio: ["pipe", "pipe", "pipe"] });
  const stdout: Buffer[] = [];
  const stderr: Buffer[] = [];
  child.stdout.on("data", chunk => stdout.push(Buffer.from(chunk as Buffer)));
  child.stderr.on("data", chunk => stderr.push(Buffer.from(chunk as Buffer)));
  child.on("error", reject);
  child.on("close", code => {
    const out = Buffer.concat(stdout).toString("utf8");
    const err = Buffer.concat(stderr).toString("utf8");
    if (code === 0) resolveProcess({ stdout: out, stderr: err });
    else reject(new Error(`${command} exited with ${code}.\n${err}`));
  });
  child.stdin.end(input ?? "");
});

const clangCommand = (): string =>
  process.env["CLANG"] || "clang";

const clangResourceInclude = async (): Promise<string> => {
  const { stdout } = await runProcess(clangCommand(), ["-print-resource-dir"]);
  return join(stdout.trim(), "include");
};

export const runClangAstDump = async (headers: string[]): Promise<string> => {
  const args = [
    "-x", "c",
    "--target=x86_64-pc-windows-msvc",
    "-fms-compatibility",
    "-fms-extensions",
    "-fsyntax-only",
    "-fno-builtin",
    "-nostdinc",
    "-isystem", await clangResourceInclude(),
    "-I", SHIM_INCLUDE_DIR,
    "-I", UCRT_INCLUDE_DIR,
    "-I", SHARED_INCLUDE_DIR,
    "-D__INTELLISENSE__=1",
    "-D_CRT_DECLARE_NONSTDC_NAMES=1",
    "-D_CRT_SECURE_NO_WARNINGS",
    "-D_CRT_NONSTDC_NO_WARNINGS",
    "-Xclang", "-ast-dump",
    "-"
  ];
  return (await runProcess(clangCommand(), args, buildClangInput(headers))).stdout;
};
