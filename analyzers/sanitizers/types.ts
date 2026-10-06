export type SanitizerTool = "ASan" | "TSan" | "UBSan" | "UBSan minimal" | "MSan" |
  "LSan" | "HWASan" | "DFSan" | "RTSan" | "TySan" | "SanitizerCoverage" | "Go race detector";

export interface SanitizerDependency {
  name: string;
  source: string;
}

export interface SanitizerSymbol {
  name: string;
  source: string;
  kind: "reference" | "definition";
}

export interface SanitizerEvidence {
  tool: SanitizerTool;
  kind: "dependency" | "reference" | "definition" | "build-setting";
  source: string;
  name: string;
}
