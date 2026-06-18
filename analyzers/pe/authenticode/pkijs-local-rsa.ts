"use strict";

import { bufferToHex } from "../../../binary-utils.js";
import { computeDigest } from "./digest-algorithms.js";
import type { Certificate, SignedData, SignerInfo } from "./pkijs-runtime.js";
import {
  CMS_MESSAGE_DIGEST_OID,
  equalBytes,
  getAttributeValue,
  getByteView,
  readOctetStringBytes,
  resolveDigestAlgorithm,
  toArrayBuffer
} from "./pkijs-support.js";
import {
  shouldVerifyRsaPkcs1v15Locally,
  verifyRsaPkcs1v15Signature
} from "./rsa-pkcs1v15.js";

export type LocalCmsSignatureVerification = {
  signatureVerified?: boolean;
  message?: string;
};

const readSignedContentBytes = (
  signedData: SignedData,
  externalData: Uint8Array | undefined
): Uint8Array | undefined => externalData ?? readOctetStringBytes(signedData.encapContentInfo.eContent);

const readSignatureInput = (
  signedData: SignedData,
  signer: SignerInfo,
  externalData: Uint8Array | undefined
): Uint8Array | undefined => signer.signedAttrs
  ? new Uint8Array(signer.signedAttrs.encodedValue)
  : readSignedContentBytes(signedData, externalData);

const verifySignedAttributesDigest = async (
  signedData: SignedData,
  signer: SignerInfo,
  externalData: Uint8Array | undefined
): Promise<string | undefined> => {
  if (!signer.signedAttrs) return undefined;
  const expected = getByteView(getAttributeValue(signer, CMS_MESSAGE_DIGEST_OID));
  const digestAlgorithm = resolveDigestAlgorithm(signer.digestAlgorithm.algorithmId);
  const content = readSignedContentBytes(signedData, externalData);
  if (!expected?.length) return "messageDigest signed attribute is absent.";
  if (!digestAlgorithm) return `Unsupported digest algorithm OID ${signer.digestAlgorithm.algorithmId}.`;
  if (!content) return "Signed content bytes are absent.";
  const computed = new Uint8Array(await computeDigest(digestAlgorithm, toArrayBuffer(content)));
  return equalBytes(computed, expected)
    ? undefined
    : `messageDigest mismatch: expected ${bufferToHex(expected)}, computed ${bufferToHex(computed)}.`;
};

export const verifySignedDataSignerWithLocalRsa = async (
  signedData: SignedData,
  signer: SignerInfo,
  signerCertificate: Certificate,
  externalData?: Uint8Array
): Promise<LocalCmsSignatureVerification | undefined> => {
  if (!shouldVerifyRsaPkcs1v15Locally(signer.signatureAlgorithm, signer.digestAlgorithm.algorithmId)) {
    return undefined;
  }
  const digestMessage = await verifySignedAttributesDigest(signedData, signer, externalData);
  if (digestMessage) return { signatureVerified: false, message: digestMessage };
  const signatureInput = readSignatureInput(signedData, signer, externalData);
  if (!signatureInput) return { message: "CMS signature input bytes are absent." };
  const localResult = await verifyRsaPkcs1v15Signature(
    signatureInput,
    signer.signature.valueBlock.valueHexView,
    signerCertificate.subjectPublicKeyInfo,
    signer.signatureAlgorithm,
    signer.digestAlgorithm.algorithmId
  );
  if (!localResult) return undefined;
  return {
    ...(localResult.verified != null ? { signatureVerified: localResult.verified } : {}),
    ...(localResult.detail ? { message: localResult.detail } : {})
  };
};
