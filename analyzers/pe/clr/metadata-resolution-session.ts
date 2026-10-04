"use strict";

import type { PeClrMetadataTables } from "./types.js";

// Retain validated decoding inputs outside the returned model. A dependency selection changes
// resolution context, so only dependent attribute/security values need decoding again.
export interface ClrResolutionSession {
  enumTypes: ReadonlyMap<string, string>;
  resolve: (enumTypes: ReadonlyMap<string, string>) => PeClrMetadataTables;
}

const sessions = new WeakMap<PeClrMetadataTables, ClrResolutionSession>();
export const registerClrResolutionSession = (tables: PeClrMetadataTables, session: ClrResolutionSession): void => {
  sessions.set(tables, session);
};
export const getClrResolutionSession = (tables: PeClrMetadataTables): ClrResolutionSession | undefined =>
  sessions.get(tables);
