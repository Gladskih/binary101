import { createReadStream, openAsBlob } from "node:fs";
import { appendFile, mkdir } from "node:fs/promises";
import { createHash } from "node:crypto";
import { basename } from "node:path";
import { DOMParser } from "@xmldom/xmldom";
import { createFileRangeReader } from "../analyzers/file-range-reader.js";
import { isPeWindowsParseResult, parsePe } from "../analyzers/pe/index.js";
import { analyzePeInstructionSets } from "../analyzers/pe/disassembly/index.js";
import { collectPeDisassemblySeeds } from "../ui/pe-disassembly-seeds.js";
import { PE32_PLUS_OPTIONAL_HEADER_MAGIC } from "../analyzers/pe/optional-header/magic.js";

const fingerprint = async (path: string): Promise<string> => {
  const hash = createHash("sha256");
  // Separate bounded streaming pass for a reproducible file identity, not another decode.
  for await (const bytes of createReadStream(path)) hash.update(bytes as Buffer);
  return hash.digest("hex");
};

const scanFile = async (path: string) => {
  const file = new File([await openAsBlob(path)], basename(path));
  const pe = await parsePe(file, text => new DOMParser({ onError: () => undefined })
    .parseFromString(text, "application/xml"));
  if (!pe || !isPeWindowsParseResult(pe)) return { path, skipped: "Not a Windows PE" };
  const seeds = await collectPeDisassemblySeeds(file, pe);
  return {
    path, sha256: await fingerprint(path), size: file.size,
    parseWarnings: pe.warnings ?? [],
    report: await analyzePeInstructionSets(createFileRangeReader(file, 0, file.size), {
      ...seeds,
      coffMachine: seeds.canonicalMachine,
      is64Bit: pe.opt.Magic === PE32_PLUS_OPTIONAL_HEADER_MAGIC,
      imageBase: pe.opt.ImageBase,
      headerRvaLimit: pe.opt.SizeOfHeaders,
      sections: pe.sections,
      rvaToOff: pe.rvaToOff,
      // Scan scheduling limit, not a format limit; reported cancellation remains visible.
      signal: AbortSignal.timeout(120_000)
    })
  };
};

const main = async (): Promise<void> => {
  if (!process.argv[2]) throw new Error("Usage: npx tsx scripts/peSpecialInstructionScan.ts <PE path> ...");
  await mkdir("scan-results/isa", { recursive: true });
  for (const path of process.argv.slice(2)) {
    const started = new Date().toISOString();
    const result = await scanFile(path).catch(error => ({ path, error: String(error) }));
    await appendFile("scan-results/isa/pe-special-instructions.jsonl",
      `${JSON.stringify({ started, ...result })}\n`);
    process.stdout.write(`${started} ${path}: ${"report" in result
      ? `${result.report.instructionCount} instructions decoded` : "skipped or failed (see report)"}\n`);
  }
};

void main().catch(error => { console.error(error); process.exitCode = 1; });
