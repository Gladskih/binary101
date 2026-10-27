import type { PeWindowsCore } from "../types.js";
import type { FileRangeReader } from "../../file-range-reader.js";

export interface EhImage {
  typeValidity: Map<number, Promise<boolean>>;
  functionInfos: Map<string, Promise<EhFunctionInfo | null>>;
  fh4UnwindMaps: Map<number, Promise<EhFunctionInfo["unwindActions"] | null>>;
  fh4SeparatedMaps: Map<string, Promise<Map<number, EhFunctionInfo["ipStates"]> | null>>;
  available: (rva: number) => number;
  read: (rva: number, size: number) => Promise<DataView | null>;
  code: (rva: number, size?: number) => boolean;
  reader: FileRangeReader;
  core: PeWindowsCore;
}

export type MsvcEhPersonality = "__CxxFrameHandler3" | "__CxxFrameHandler4" | "__C_specific_handler"
  | "_except_handler3" | "_except_handler4";

export interface EhFunctionSymbol { rva: number; name: string; source: "COFF" | "CodeView"; }

export interface EhHandler {
  handlerRva: number;
  typeDescriptorRva: number;
  continuationRvas: number[];
}

export interface EhTryBlock {
  tryLow: number;
  tryHigh: number;
  catchHigh: number;
  handlers: EhHandler[];
}

export interface EhFunctionInfo {
  rva: number;
  version: 3 | 4;
  unwindActions: { toState: number; actionRva: number }[];
  tryBlocks: EhTryBlock[];
  ipStates: { ipRva: number; state: number }[];
}

interface MsvcEhEvidence {
  unwindInfoRva?: number;
  handlerRva: number;
  personality?: MsvcEhPersonality;
  evidence: string;
  functionRvas: number[];
}

export type MsvcEhRecord = MsvcEhEvidence & (
  | { functionInfo: EhFunctionInfo; scopes?: never; scopeTableRva?: never; registration?: never }
  | { functionInfo?: never; scopeTableRva: number; registration?: never;
    scopes: { beginRva: number; endRva: number; filterRva: number; targetRva: number }[] }
  | { registration: "_except_handler3" | "_except_handler4"; functionInfo?: never;
    scopes?: never; scopeTableRva?: never }
);

export interface MsvcEhAnalysis {
  records: MsvcEhRecord[];
  warnings: string[];
}
