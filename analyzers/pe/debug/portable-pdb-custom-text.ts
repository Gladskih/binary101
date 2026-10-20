import { ClrHeapReaders } from "../clr/metadata-heaps.js";
import { PortablePdbBlobReader } from "./portable-pdb-blob.js";
import type { PortablePdbCustomData, PortablePdbCompilationReference } from "./portable-pdb-custom-types.js";

// Language-specific custom records, including UTF-8 option/reference fields.
// https://github.com/dotnet/runtime/blob/main/docs/design/specs/PortablePdb-Metadata.md
const utf8 = (bytes: Uint8Array): string =>
  new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(bytes);

const validateSourceLinkPattern = (pattern: string, url: string, paths: Set<string>): void => {
  // Source Link JSON schema: matching single wildcard, at the end of the file path.
  // https://github.com/dotnet/designs/blob/main/accepted/2020/diagnostics/source-link.md
  const wildcards = pattern.split("*").length - 1;
  if (wildcards > 1 || (wildcards === 1 && !pattern.endsWith("*")) ||
      wildcards !== url.split("*").length - 1) {
    throw new Error("Source Link wildcard patterns are inconsistent");
  }
  if (paths.has(pattern.toLowerCase())) throw new Error("Source Link contains duplicate case-insensitive paths");
  paths.add(pattern.toLowerCase());
};

const sourceLink = (bytes: Uint8Array): PortablePdbCustomData => {
  const value: unknown = JSON.parse(utf8(bytes));
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("Source Link must contain a JSON object");
  }
  const documents: unknown = (value as { documents?: unknown }).documents;
  if (!documents || typeof documents !== "object" || Array.isArray(documents)) {
    throw new Error("Source Link documents must contain a path-to-URL object");
  }
  if (!Object.keys(documents).length) throw new Error("Source Link documents map is empty");
  const paths = new Set<string>();
  return { type: "sourceLink", documents: Object.entries(documents).map(([pattern, url]) => {
    if (typeof url !== "string") throw new Error("Source Link URL is not a string");
    validateSourceLinkPattern(pattern, url, paths);
    return { pattern, url };
  }) };
};

const compilationOptions = (bytes: Uint8Array): PortablePdbCustomData => {
  const reader = new PortablePdbBlobReader(bytes);
  const options: { name: string; value: string }[] = [];
  const names = new Set<string>();
  while (reader.remaining) {
    const name = reader.utf8z();
    const value = reader.utf8z();
    if (names.has(name)) throw new Error("compilation options contain a duplicate name");
    names.add(name);
    options.push({ name, value });
  }
  return { type: "options", options };
};

const compilationReferences = (bytes: Uint8Array): PortablePdbCustomData => {
  const reader = new PortablePdbBlobReader(bytes);
  const references: PortablePdbCompilationReference[] = [];
  while (reader.remaining) {
    const fileName = reader.utf8z();
    const aliases = reader.utf8z();
    const flags = reader.byte();
    const timeStamp = reader.uint32();
    const fileSize = reader.uint32();
    const mvid = new ClrHeapReaders({ guid: reader.take(16), strings: null,
      blob: null, userString: null }, []).getGuid(1, "Compilation reference MVID");
    references.push({ fileName, aliases, flags, timeStamp, fileSize, mvid });
  }
  return { type: "references", references };
};

const tupleNames = (bytes: Uint8Array): PortablePdbCustomData => {
  const reader = new PortablePdbBlobReader(bytes);
  const names: string[] = [];
  while (reader.remaining) names.push(reader.utf8z());
  return { type: "tupleNames", names };
};

const DECODERS: Readonly<Record<string, (bytes: Uint8Array) => PortablePdbCustomData>> = {
  sourceLink, options: compilationOptions, references: compilationReferences, tupleNames,
  defaultNamespace: bytes => ({ type: "defaultNamespace", name: utf8(bytes) })
};

export const decodeCustomText = (type: string, bytes: Uint8Array): PortablePdbCustomData => {
  if (!Object.hasOwn(DECODERS, type)) throw new Error(`unsupported custom text record ${type}`);
  return DECODERS[type]!(bytes);
};
