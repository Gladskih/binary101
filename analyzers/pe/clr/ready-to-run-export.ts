import type { FileRangeReader } from "../../file-range-reader.js";
import type { PeExportEntry } from "../directories/exports.js";
import type { RvaToOffset } from "../types.js";
import type { PeClrReadyToRun } from "./ready-to-run-types.js";
import { parseReadyToRunImageHeader } from "./ready-to-run.js";

const invalidExport = (message: string): PeClrReadyToRun => ({
  status: "unmapped", signature: null, majorVersion: null, minorVersion: null,
  flags: null, sectionCount: 0, sections: [], issues: [message]
});

export const parseExportedReadyToRun = async (
  reader: FileRangeReader, mapper: RvaToOffset, entries: PeExportEntry[], machine?: number
): Promise<PeClrReadyToRun | null> => {
  // The runtime's PEReaderExtensions.TryGetCompositeReadyToRunHeader uses this data export.
  // https://github.com/dotnet/runtime/blob/v10.0.0/src/coreclr/tools/aot/ILCompiler.Reflection.ReadyToRun/PEReaderExtensions.cs
  const headers = entries.filter(entry => entry.names.includes("RTR_HEADER"));
  if (!headers.length) return null;
  if (headers.length !== 1) return invalidExport("RTR_HEADER export is ambiguous.");
  if (headers[0]!.forwarder) return invalidExport("RTR_HEADER cannot be a forwarded export.");
  return parseReadyToRunImageHeader(reader, mapper, headers[0]!.rva, undefined, machine);
};
