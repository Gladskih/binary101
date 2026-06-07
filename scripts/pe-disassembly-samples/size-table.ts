"use strict";

import type { SampleSummary, SuccessfulSampleResult } from "./model.js";

interface BinarySizeRow {
  arch: string;
  compiler: string;
  language: string;
  mode: string;
  runtimeLinkage: string;
  sizeBytes: number;
  sizeKib: string;
  variantId: string;
}

const describeSuccess = (result: SuccessfulSampleResult): BinarySizeRow => ({
  ...result.sizeTableColumns,
  language: result.language,
  sizeBytes: result.outputSize,
  sizeKib: (result.outputSize / 1024).toFixed(1),
  variantId: result.id
});

const renderRow = (row: BinarySizeRow): string =>
  `| ${row.language} | ${row.arch} | ${row.compiler} | ${row.mode} | ${row.runtimeLinkage} | ` +
  `${row.sizeBytes} | ${row.sizeKib} | ${row.variantId} |`;

export const buildBinarySizeMarkdown = (summary: SampleSummary): string => {
  const rows = summary.results
    .filter((result): result is SuccessfulSampleResult => result.kind === "success")
    .map(describeSuccess);
  return [
    "# PE Disassembly Sample Binary Sizes",
    "",
    "Generated from `summary.json` by `scripts/pe-disassembly-samples/size-table.ts`.",
    "",
    "The build pipeline validates primary PE outputs before they enter `summary.json`.",
    "Those outputs should have no COFF symbol records in the executable.",
    "The authentic Go internal linker may leave an empty COFF pointer with zero records.",
    "Adjacent PDB files may still exist for toolchains that emit them.",
    "",
    "| language | arch | compiler | mode | runtime linkage | size bytes | size KiB | variant id |",
    "|---|---|---|---|---|---:|---:|---|",
    ...rows.map(renderRow),
    ""
  ].join("\n");
};
