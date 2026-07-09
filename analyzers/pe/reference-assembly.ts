"use strict";

import type { PeClrHeader } from "./clr/types.js";
import { TABLE_ASSEMBLY } from "./clr/metadata-schema.js";

export type PeReferenceAssemblySubtype = "dotnet-reference-assembly";

// Microsoft Learn documents ReferenceAssemblyAttribute as the assembly-level
// marker for reference assemblies, which contain metadata but no executable
// implementation for runtime loading.
// https://learn.microsoft.com/en-us/dotnet/api/system.runtime.compilerservices.referenceassemblyattribute
const REFERENCE_ASSEMBLY_ATTRIBUTE =
  "System.Runtime.CompilerServices.ReferenceAssemblyAttribute";

export const detectPeReferenceAssemblySubtypeFromClr = (
  clr: PeClrHeader
): PeReferenceAssemblySubtype | null =>
  clr.meta?.tables?.customAttributes.some(attribute =>
    attribute.parent.tableId === TABLE_ASSEMBLY &&
    attribute.attributeType === REFERENCE_ASSEMBLY_ATTRIBUTE
  )
    ? "dotnet-reference-assembly"
    : null;

export const isPeReferenceAssembly = (pe: { subtype?: string | null }): boolean =>
  pe.subtype === "dotnet-reference-assembly";
