import type { AuthenticodeInfo } from "./index.js";
import { describeOid } from "./pkcs7-oids.js";

export const collectDigestAlgorithmConsistencyWarnings = (
  info: Partial<AuthenticodeInfo>
): string[] => {
  const signers = info.signers ?? [];
  if (!info.digestAlgorithms || info.signerCount !== signers.length ||
      signers.some(signer => !signer.digestAlgorithm)) return [];
  const declared = new Set(info.digestAlgorithms);
  const used = new Set(signers.map(signer => describeOid(signer.digestAlgorithm)!));
  // RFC 5652 section 5.1: each listed algorithm is used by one or more signers.
  // Section 5.3 uses SHOULD for inclusion of each SignerInfo digest algorithm.
  // https://www.rfc-editor.org/rfc/rfc5652.html#section-5.1
  return [
    ...[...declared].filter(algorithm => !used.has(algorithm)).map(algorithm =>
      `SignedData digestAlgorithms lists ${algorithm}, but no SignerInfo uses it (RFC 5652 section 5.1).`
    ),
    ...[...used].filter(algorithm => !declared.has(algorithm)).map(algorithm =>
      `SignerInfo uses ${algorithm}, which is absent from SignedData digestAlgorithms (RFC 5652 section 5.3 recommends inclusion).`
    )
  ];
};
