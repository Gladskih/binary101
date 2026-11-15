import type { IcedInstructionObject, IcedX86Module } from "../x86/disassembly-iced.js";
import { getNearBranchTarget } from "../x86/disassembly-branch-targets.js";
import type { ElfImportLinkage } from "./import-linkage.js";
import type { ElfRelocationInfo } from "./relocation-types.js";
import { getX86DirectMemoryBranch } from "../x86/direct-memory-reference.js";

interface CodeReference {
  kind: string;
  count: number;
  sampleAddresses: bigint[];
}

export interface ElfImportCodeEvidence {
  slotAddress: bigint;
  stubAddresses: bigint[];
  references: CodeReference[];
}

const recordReference = (references: Map<string, CodeReference>,
  kind: string, address: bigint): void => {
  const reference = references.get(kind) ?? { kind, count: 0, sampleAddresses: [] };
  reference.count++;
  // Bounded examples, independent of the total number of decoded instruction sites.
  if (reference.sampleAddresses.length < 3) reference.sampleAddresses.push(address);
  references.set(kind, reference);
};

const mergeReference = (references: Map<string, CodeReference>, reference: CodeReference): void => {
  const previous = references.get(reference.kind);
  references.set(reference.kind, { kind: reference.kind,
    count: (previous?.count ?? 0) + reference.count,
    sampleAddresses: [...(previous?.sampleAddresses ?? []), ...reference.sampleAddresses].slice(0, 3)
  });
};

export const createElfImportCodeCollector = (iced: IcedX86Module,
  linkage?: ElfImportLinkage, relocations?: ElfRelocationInfo) => {
  const slots = new Set((linkage?.links ?? []).filter(link =>
    (link.kind === "PLT slot" || link.kind === "GOT slot") && link.loadSegments.length === 1)
    .flatMap(link => relocations?.entries[link.relocationIndex]?.offset ?? []));
  const references = new Map<bigint, Map<string, CodeReference>>();
  const stubs = new Map<bigint, bigint>();
  const branches = new Map<bigint, Map<string, CodeReference>>();
  const landingPads = new Map<bigint, bigint>();
  const record = (instruction: IcedInstructionObject): void => {
    if (!slots.size || instruction.code === iced.Code["INVALID"]) return;
    if (instruction.code === iced.Code["Endbr64"] || instruction.code === iced.Code["Endbr32"]) {
      landingPads.set(instruction.nextIP, instruction.ip);
    }
    const target = getNearBranchTarget(instruction, iced.OpKind);
    const flow = instruction.flowControl;
    if (target != null && (flow === iced.FlowControl["Call"] ||
      flow === iced.FlowControl["UnconditionalBranch"])) {
      const edges = branches.get(target) ?? new Map<string, CodeReference>();
      recordReference(edges, flow === iced.FlowControl["Call"] ? "Call to stub" : "Jump to stub",
        instruction.ip);
      branches.set(target, edges);
    }
    const branch = getX86DirectMemoryBranch(iced, instruction);
    if (!branch || !slots.has(branch.address)) return;
    const slot = branch.address;
    const sites = references.get(slot) ?? new Map<string, CodeReference>();
    recordReference(sites, branch.kind === "call" ? "Indirect call" : "Indirect jump",
      instruction.ip);
    references.set(slot, sites);
    if (branch.kind !== "jump") return;
    stubs.set(instruction.ip, slot);
    const landingPad = landingPads.get(instruction.ip);
    if (landingPad != null) stubs.set(landingPad, slot);
  };
  const findings = (): ElfImportCodeEvidence[] => {
    const evidence = new Map([...references].map(([slot, sites]) => [slot, {
      slotAddress: slot, stubAddresses: [] as bigint[], references: new Map(sites)
    }]));
    for (const [address, slot] of stubs) {
      const entry = evidence.get(slot)!;
      entry.stubAddresses.push(address);
      for (const reference of branches.get(address)?.values() ?? []) {
        mergeReference(entry.references, reference);
      }
    }
    return [...evidence.values()].map(entry => ({ ...entry, references: [...entry.references.values()] }));
  };
  return { record, findings };
};
