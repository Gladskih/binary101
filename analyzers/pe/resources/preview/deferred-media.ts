import type { ResourcePayloadReader } from "../payload-reader.js";
import type { ResourceLangWithPreview, ResourcePreviewResult } from "./types.js";
import { hasPngSignature, hasJpegSignature, hasGifSignature, hasBmpSignature,
  hasWebpSignature, hasRiffForm, hasTrueTypeSfntSignature, hasOpenTypeCffSignature,
  hasWoffSignature, hasWoff2Signature } from "../../../probes/file-signatures.js";

const hasReadableLocation = (leaf: ResourceLangWithPreview): boolean =>
  Number.isSafeInteger(leaf.size) && leaf.size > 2 * 1024 * 1024 &&
  leaf.dataFileOffset !== null && Number.isSafeInteger(leaf.dataFileOffset) && leaf.dataFileOffset >= 0;

export const deferLargeResourceMedia = async (
  reader: ResourcePayloadReader, type: string, leaf: ResourceLangWithPreview
): Promise<ResourcePreviewResult | null> => {
  // Automatic display budget, never an accepted-data limit. The complete payload remains
  // addressable and can be previewed explicitly without truncation.
  if (!hasReadableLocation(leaf)) return null;
  const prefix = reader.readResourceBytes ? await reader.readResourceBytes(leaf.dataRVA, 16)
    : await reader.readBytes(leaf.dataFileOffset!, 16);
  if (prefix.length < 16) return null;
  const image = [hasPngSignature, hasJpegSignature, hasGifSignature, hasBmpSignature, hasWebpSignature]
    .some(probe => probe(prefix));
  const font = [hasTrueTypeSfntSignature, hasOpenTypeCffSignature, hasWoffSignature, hasWoff2Signature]
    .some(probe => probe(prefix));
  if (!image && !font && !hasRiffForm(prefix, "WAVE") &&
    !["BITMAP", "ICON", "CURSOR", "FONT"].includes(type)) return null;
  return { preview: { previewKind: "deferred" } };
};
