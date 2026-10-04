"use strict";

import { ClrAssemblyCatalog } from "./metadata-assembly-catalog.js";
import { parseSerializedEnumName } from "./metadata-enum-name.js";
import { createEnclosingTypeRoots } from "./metadata-type-scopes.js";
import { getClrResolutionSession, registerClrResolutionSession } from "./metadata-resolution-session.js";
import type { PeClrMetadataTables } from "./types.js";

class DependencyEnumTypes extends Map<string, string> {
  private readonly cache = new Map<string, string | undefined>();
  private readonly scopes: ReadonlyMap<number, number | null>;
  private readonly typeIndexes = new WeakMap<PeClrMetadataTables, Map<string, number | null>>();
  private readonly exportedIndexes = new WeakMap<PeClrMetadataTables, Map<string, number | null>>();
  private readonly exportedRoots = new WeakMap<PeClrMetadataTables, ReadonlyMap<number, number | null>>();

  constructor(private readonly source: PeClrMetadataTables, private readonly assemblies: ClrAssemblyCatalog,
    private readonly issues: string[]) {
    super();
    this.scopes = createEnclosingTypeRoots(source.typeRefs.map(type => type.resolutionScope), 1);
  }

  override get(name: string): string | undefined {
    if (this.cache.has(name)) return this.cache.get(name);
    const reference = /^TypeRef#(\d+) \((.*)\)$/s.exec(name);
    const value = reference ? this.referenceType(Number(reference[1]), reference[2]!) : this.serializedType(name);
    this.cache.set(name, value);
    return value;
  }

  private referenceType(row: number, name: string): string | undefined {
    const root = this.scopes.get(row);
    if (!root || this.source.typeRefs[row - 1]?.fullName !== name) return undefined;
    const scope = this.source.typeRefs[root - 1]!.resolutionScope;
    // ECMA-335 II.22.38: a null ResolutionScope locates the type through ExportedType.
    if (scope.raw === 0) {
      const forwarded = this.forwardedAssembly(this.source, name);
      return forwarded ? this.enumType(forwarded, name) : undefined;
    }
    // ECMA-335 II.22.38 ResolutionScope: Module=0, AssemblyRef=35.
    const assembly = scope.tableId === 0 ? this.source : scope.tableId === 35
      ? this.assemblies.resolveReference(this.source.assemblyRefs[scope.row - 1]) : null;
    return assembly ? this.enumType(assembly, name) : undefined;
  }

  private serializedType(name: string): string | undefined {
    const parsed = parseSerializedEnumName(name);
    if (!parsed) { this.issues.push(`Serialized enum type name is malformed: ${name}.`); return undefined; }
    const assembly = parsed.assembly ? this.assemblies.resolveName(parsed.assembly) : this.source;
    return assembly ? this.enumType(assembly, parsed.typeName) : undefined;
  }

  private enumType(start: PeClrMetadataTables, name: string): string | undefined {
    const visited = new Set<PeClrMetadataTables>();
    let assembly: PeClrMetadataTables | null = start;
    while (assembly && !visited.has(assembly)) {
      visited.add(assembly);
      if (this.typeIndex(assembly).has(name)) return this.typeIndex(assembly).get(name)
        ? getClrResolutionSession(assembly)?.enumTypes.get(name) : undefined;
      assembly = this.forwardedAssembly(assembly, name);
    }
    if (assembly) this.issues.push(`Type forwarding cycle for enum ${name}.`);
    return undefined;
  }

  private typeIndex(assembly: PeClrMetadataTables): Map<string, number | null> {
    return this.nameIndex(assembly, this.typeIndexes, assembly.typeDefs);
  }

  private nameIndex(assembly: PeClrMetadataTables, cache: WeakMap<PeClrMetadataTables, Map<string, number | null>>,
    types: Array<{ row: number; fullName: string | null }>): Map<string, number | null> {
    const cached = cache.get(assembly);
    if (cached) return cached;
    const index = new Map<string, number | null>();
    for (const type of types) if (type.fullName) index.set(type.fullName, index.has(type.fullName) ? null : type.row);
    cache.set(assembly, index);
    return index;
  }

  private forwardedAssembly(assembly: PeClrMetadataTables, name: string): PeClrMetadataTables | null {
    const row = this.nameIndex(assembly, this.exportedIndexes, assembly.exportedTypes).get(name);
    if (!row) return null;
    if (!this.exportedRoots.has(assembly)) this.exportedRoots.set(assembly,
      createEnclosingTypeRoots(assembly.exportedTypes.map(type => type.implementation), 39));
    const root = this.exportedRoots.get(assembly)!.get(row);
    const type = root ? assembly.exportedTypes[root - 1] : undefined;
    // ECMA-335 II.6.8 / II.22.14: Forwarder=0x00200000; destination must be AssemblyRef.
    return type && (type.flags & 0x00200000) && type.implementation.tableId === 35
      ? this.assemblies.resolveReference(assembly.assemblyRefs[type.implementation.row - 1]) : null;
  }
}

export const resolveClrMetadataDependencies = (
  tables: PeClrMetadataTables, dependencies: PeClrMetadataTables[]
): PeClrMetadataTables => {
  const session = getClrResolutionSession(tables);
  if (!session) return { ...tables, issues: [...tables.issues ?? [], "CLR decoding inputs are unavailable."] };
  const issues: string[] = [];
  const resolved = session.resolve(new DependencyEnumTypes(tables,
    new ClrAssemblyCatalog(tables.assembly ? [tables, ...dependencies] : dependencies, issues), issues));
  const updated = issues.length
    ? { ...resolved, issues: [...new Set([...resolved.issues ?? [], ...issues])] } : resolved;
  registerClrResolutionSession(updated, session);
  return updated;
};
