import type { Amd64UnwindOperation, Amd64UnwindV12Header } from "./unwind-v12-types.js";

export interface Amd64PrologDescription extends Amd64UnwindV12Header {
  version: number;
  flags: number;
  operations: Amd64UnwindOperation[];
  complete: boolean;
}

export interface Amd64PrologIssue {
  code: "prolog-size" | "operation-boundary" | "operation-mismatch" | "undescribed-stack";
  offset: number;
  expected?: string;
  actual?: string;
}

export interface Amd64PrologCheck {
  issues: Amd64PrologIssue[];
  limitations: string[];
}

export interface Amd64PrologFinding extends Amd64PrologCheck {
  beginRva: number;
  endRva: number;
  unwindInfoRva: number;
}

export interface Amd64PrologReport {
  matchedCount: number;
  unverifiedCounts: Record<string, number>;
  findings: Amd64PrologFinding[];
}
