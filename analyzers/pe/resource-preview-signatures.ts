"use strict";

// Re-export shared probe predicates so PE resource preview and top-level detection use the same
// low-level signature knowledge.
export {
  hasBmpSignature,
  hasBytePrefix,
  hasGifSignature,
  hasJpegSignature,
  hasOpenTypeCffSignature,
  hasPdfHeader,
  hasPngSignature,
  hasRiffForm,
  hasTrueTypeSfntSignature,
  hasWebpSignature,
  hasWoffSignature,
  hasWoff2Signature,
  hasZipLocalFileHeader
} from "../probes/file-signatures.js";
