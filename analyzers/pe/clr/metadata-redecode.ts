"use strict";

import type { PeClrMetadataTables, PeClrAdditionalTable } from "./types.js";
import type { ClrParsedTableStream } from "./metadata-table-reader.js";
import type { ClrHeapReaders } from "./metadata-heaps.js";
import { createCustomAttributes, type ClrMetadataReferenceGraph } from "./metadata-custom-attributes.js";
import { registerClrResolutionSession, type ClrResolutionSession } from "./metadata-resolution-session.js";
import { parsePermissionSet } from "./metadata-security.js";

const decodeSecurity = (
  tables: PeClrAdditionalTable[], parsed: ClrParsedTableStream,
  heaps: ClrHeapReaders, enumTypes: ReadonlyMap<string, string>
): PeClrAdditionalTable[] => {
  const decode = (bytes: Uint8Array | null, context: string) =>
    bytes ? parsePermissionSet(bytes, context, enumTypes) : null;
  return tables.map(table => table.tableId !== 0x0e ? table : { ...table,
    rows: table.rows.map((row, index) => {
      const blobIndex = parsed.tables.get(0x0e)?.rows[index]?.["PermissionSet"];
      return { ...row, PermissionSet: heaps.decodeBlob(typeof blobIndex === "number" ? blobIndex : 0,
        `DeclSecurity row ${index + 1}`, decode) };
    })
  });
};

export const attachClrResolutionSession = (
  tables: PeClrMetadataTables, parsed: ClrParsedTableStream, heaps: ClrHeapReaders,
  references: ClrMetadataReferenceGraph
): void => {
  const session: ClrResolutionSession = { enumTypes: references.enumTypes ?? new Map(), resolve: enumTypes => {
    const updated: PeClrMetadataTables = { ...tables,
      customAttributes: createCustomAttributes(parsed.tables.get(0x0c)?.rows ?? [], heaps,
        { ...references, enumTypes }),
      additionalTables: decodeSecurity(tables.additionalTables ?? [], parsed, heaps, enumTypes)
    };
    registerClrResolutionSession(updated, session);
    return updated;
  } };
  registerClrResolutionSession(tables, session);
};
