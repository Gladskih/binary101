"use strict";

import { clrAssemblyIdentityKey, getClrAssemblyIdentity, type ClrAssemblyIdentity } from "./metadata-assembly-identity.js";
import type { PeClrAssemblyRefInfo, PeClrMetadataTables } from "./types.js";

const matchesIdentity = (candidate: ClrAssemblyIdentity, identity: Partial<ClrAssemblyIdentity>): boolean =>
  Object.entries(identity).every(([key, value]) => key === "version"
    ? candidate.version === value || candidate.version.startsWith(`${value}.`)
    : candidate[key as keyof ClrAssemblyIdentity] === value);

export class ClrAssemblyCatalog {
  private readonly identities = new Map<string, PeClrMetadataTables | null>();
  private readonly named = new Map<string, PeClrMetadataTables[]>();

  constructor(tables: PeClrMetadataTables[], private readonly issues: string[]) {
    for (const table of new Set(tables)) {
      const identity = getClrAssemblyIdentity(table.assembly);
      if (!identity) { issues.push("Dependency assembly identity is absent or malformed."); continue; }
      const key = clrAssemblyIdentityKey(identity);
      this.identities.set(key, this.identities.has(key) ? null : table);
      this.named.set(identity.name, [...this.named.get(identity.name) ?? [], table]);
    }
  }

  resolveReference(reference: PeClrAssemblyRefInfo | undefined): PeClrMetadataTables | null {
    const identity = getClrAssemblyIdentity(reference ?? null);
    const assembly = identity ? this.identities.get(clrAssemblyIdentityKey(identity)) : undefined;
    if (assembly) return assembly;
    this.issues.push(`Assembly dependency ${reference?.name ?? "(invalid reference)"} ` +
      `${reference?.version ?? ""} is ${assembly === null ? "ambiguous" : "unavailable or mismatched"}.`);
    return null;
  }

  resolveName(identity: Partial<ClrAssemblyIdentity>): PeClrMetadataTables | null {
    const candidates = (this.named.get(identity.name ?? "") ?? [])
      .filter(table => matchesIdentity(getClrAssemblyIdentity(table.assembly)!, identity));
    if (candidates.length === 1) return candidates[0]!;
    this.issues.push(`Assembly dependency ${identity.name} is ` +
      `${candidates.length ? "ambiguous" : "unavailable or mismatched"}.`);
    return null;
  }
}
