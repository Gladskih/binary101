import assert from "node:assert/strict";
import { test } from "node:test";
import { execFileSync } from "node:child_process";
import { mkdir, readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { legacyReader } from "../fixtures/pe-legacy-codeview.js";
import { readLegacyCodeViewSymbols } from "../../analyzers/pe/debug/legacy-codeview-symbols.js";
import { analyzeCodeViewLocalScopes } from "../../analyzers/pe/debug/codeview-local-scopes.js";

const nativeInlineSymbols = async () => {
  const root = resolve("scan-results/inline-native");
  await mkdir(root, { recursive: true });
  const object = resolve(root, "inline.obj");
  const pdb = resolve(root, "inline.pdb");
  execFileSync("C:/Program Files/LLVM/bin/clang-cl.exe", ["/nologo", "/Z7", "/O2", "/GS-", "/c",
    resolve("tests/external/pe-debug-native/CodeViewInlineContexts.c"), `/Fo${object}`]);
  execFileSync("C:/Program Files/LLVM/bin/lld-link.exe", ["/dll", "/noentry", "/nodefaultlib", "/debug",
    "/incremental:no", `/out:${resolve(root, "inline.dll")}`, `/pdb:${pdb}`, object]);
  const oracle = execFileSync("C:/Program Files/LLVM/bin/llvm-pdbutil.exe",
    ["dump", "-modules", "-symbols", "-modi=0", pdb], { encoding: "utf8" });
  const stream = /debug stream: (\d+)/.exec(oracle)!;
  const raw = resolve(root, "module.bin");
  execFileSync("C:/Program Files/LLVM/bin/llvm-pdbutil.exe", ["export", `--stream=${stream[1]}`, `--out=${raw}`, pdb]);
  return { oracle, bytes: await readFile(raw) };
};

const annotationFromOracle = (line: string) => {
  const code = /code(?: end)? 0x[\dA-Fa-f]+ \(\+0x([\dA-Fa-f]+)\)/.exec(line);
  const source = /line -?\d+ \(([+-]?\d+)\)/.exec(line);
  if (code && source) return { opcode: 11, operands: [Number.parseInt(code[1]!, 16), Number(source[1])] };
  if (code) return { opcode: line.includes("code end") ? 4 : 3, operands: [Number.parseInt(code[1]!, 16)] };
  assert.ok(source);
  return { opcode: 6, operands: [Number(source[1])] };
};

const inlineFromOracle = (oracle: string, header: RegExpExecArray, end: number | undefined) => {
  const text = oracle.slice(header.index, end);
  const fields = /inlinee = 0x([\dA-Fa-f]+)[^\n]*parent = (\d+), end = (\d+)/.exec(text)!;
  return { kind: "inline", inlinee: Number.parseInt(fields[1]!, 16),
    scopeOffsets: { parent: Number(fields[2]), end: Number(fields[3]) },
    annotations: text.split("\n").filter(line => /^\s+[\dA-Fa-f]+\s+(?:code|line)/.test(line)).map(annotationFromOracle) };
};

// Genuine compiler/linker symbol stream and unchanged LLVM oracle; never execute the DLL.
void test("Native inline parent/end links and local contexts agree with unchanged LLVM", async () => {
  const { oracle, bytes } = await nativeInlineSymbols();
  const headers = [...oracle.matchAll(/^\s+(\d+) \| (S_\w+) \[size = (\d+)\]/gm)];
  const last = headers.at(-1)!;
  const warnings: string[] = [];
  const parsed = await readLegacyCodeViewSymbols(legacyReader(bytes, warnings), 4, Number(last[1]) + Number(last[3]));
  const result = analyzeCodeViewLocalScopes(parsed);
  const inlines = parsed.records.filter(record => record.scope?.kind === "inline");

  assert.equal(inlines.length, 2);
  assert.deepEqual(inlines.map(record => record.scope), headers.flatMap((header, index) =>
    header[2] === "S_INLINESITE" ? [inlineFromOracle(oracle, header, headers[index + 1]?.index)] : []));
  assert.deepEqual(result.issues, []);
  assert.deepEqual(result.bindings.flatMap(binding => binding.issues), []);
  assert.equal(result.bindings.filter(binding => binding.record.name === "scaled" && binding.context?.scope?.kind === "inline").length, 2);
  assert.deepEqual(warnings, []);
});
