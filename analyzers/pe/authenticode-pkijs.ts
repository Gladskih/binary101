"use strict";

import { fromBER } from "asn1js";
import { ContentInfo, SignedData } from "./pkijs-runtime.js";
import type {
  AuthenticodeSignerVerificationInfo,
  AuthenticodeVerificationInfo
} from "./authenticode.js";

const PKCS7_SIGNED_DATA_OID = "1.2.840.113549.1.7.2";

type AuthenticodeSignatureVerification = Pick<
  AuthenticodeVerificationInfo,
  "signerVerifications" | "warnings"
>;

const describeError = (error: unknown): string =>
  error instanceof Error ? error.message : String(error);

const toArrayBuffer = (bytes: Uint8Array): ArrayBuffer => {
  const out = new Uint8Array(bytes.byteLength);
  out.set(bytes);
  return out.buffer;
};

const getBlockDiagnostics = (
  block: object
): { error?: string; warnings?: string[] } => {
  const error = Reflect.get(block, "error");
  const warnings = Reflect.get(block, "warnings");
  return {
    ...(typeof error === "string" && error ? { error } : {}),
    ...(Array.isArray(warnings)
      ? {
          warnings: warnings.filter(
            (warning): warning is string =>
              typeof warning === "string" && warning.length > 0
          )
        }
      : {})
  };
};

const getErrorProperty = (error: unknown, name: string): unknown =>
  error && typeof error === "object" ? Reflect.get(error, name) : undefined;

const buildSignerVerification = (
  index: number,
  message: string | undefined,
  code: number | undefined,
  signatureVerified: boolean | null | undefined,
  signerCertificateVerified: boolean | null | undefined
): AuthenticodeSignerVerificationInfo => ({
  index,
  ...(typeof code === "number" ? { code } : {}),
  ...(message ? { message } : {}),
  ...(typeof signatureVerified === "boolean" ? { signatureVerified } : {}),
  ...(typeof signerCertificateVerified === "boolean" ? { signerCertificateVerified } : {})
});

const mergeWarnings = (warnings: string[]): string[] | undefined => {
  const merged = [...new Set(warnings)];
  return merged.length ? merged : undefined;
};

const withWarnings = (warnings: string[]): AuthenticodeSignatureVerification => {
  const mergedWarnings = mergeWarnings(warnings);
  return mergedWarnings ? { warnings: mergedWarnings } : {};
};

const normalizeSignerMessage = (
  message: string | undefined,
  signatureVerified: boolean | undefined
): string | undefined =>
  message || (signatureVerified === false ? "Signature verification returned false." : undefined);

const verifySigner = async (
  signedData: SignedData,
  signerIndex: number,
  warnings: string[]
): Promise<AuthenticodeSignerVerificationInfo> => {
  try {
    const result = await signedData.verify({
      signer: signerIndex,
      checkChain: false,
      extendedMode: true
    });
    const message = normalizeSignerMessage(result.message, result.signatureVerified ?? undefined);
    if (message && result.signatureVerified === false) {
      warnings.push(`Signer ${signerIndex + 1}: ${message}`);
    }
    return buildSignerVerification(
      signerIndex,
      message,
      result.code,
      result.signatureVerified,
      result.signerCertificateVerified
    );
  } catch (error) {
    const message = describeError(error);
    const code = getErrorProperty(error, "code");
    const signatureVerified = getErrorProperty(error, "signatureVerified");
    const signerCertificateVerified = getErrorProperty(error, "signerCertificateVerified");
    warnings.push(`Signer ${signerIndex + 1}: ${message}`);
    return buildSignerVerification(
      signerIndex,
      message,
      typeof code === "number" ? code : undefined,
      typeof signatureVerified === "boolean" ? signatureVerified : undefined,
      typeof signerCertificateVerified === "boolean" ? signerCertificateVerified : undefined
    );
  }
};

export const verifyPkcs7Signatures = async (
  payload: Uint8Array
): Promise<AuthenticodeSignatureVerification> => {
  const warnings: string[] = [];
  const ber = fromBER(toArrayBuffer(payload));
  const diagnostics = getBlockDiagnostics(ber.result as object);
  if (diagnostics.error) {
    warnings.push(`PKI.js BER parse error: ${diagnostics.error}`);
  }
  diagnostics.warnings?.forEach(warning => warnings.push(`PKI.js BER warning: ${warning}`));
  if (ber.offset === -1) {
    const mergedWarnings = mergeWarnings(warnings);
    return mergedWarnings
      ? { warnings: mergedWarnings }
      : { warnings: ["PKI.js could not decode the PKCS#7 payload."] };
  }
  if (ber.offset < payload.byteLength) {
    warnings.push("PKI.js BER parser reported trailing bytes after the CMS structure.");
  }

  let contentInfo: ContentInfo;
  try {
    contentInfo = new ContentInfo({ schema: ber.result });
  } catch (error) {
    warnings.push(`PKI.js could not parse ContentInfo: ${describeError(error)}`);
    return withWarnings(warnings);
  }

  if (contentInfo.contentType !== PKCS7_SIGNED_DATA_OID) {
    warnings.push(`PKI.js expected SignedData but found ${contentInfo.contentType}.`);
    return withWarnings(warnings);
  }
  if (!contentInfo.content) {
    warnings.push("PKI.js SignedData payload is missing.");
    return withWarnings(warnings);
  }

  let signedData: SignedData;
  try {
    signedData = new SignedData({ schema: contentInfo.content });
  } catch (error) {
    warnings.push(`PKI.js could not parse SignedData: ${describeError(error)}`);
    return withWarnings(warnings);
  }
  if (!signedData.signerInfos.length) {
    warnings.push("PKI.js SignedData does not contain any signer infos.");
    return withWarnings(warnings);
  }

  const signerVerifications: AuthenticodeSignerVerificationInfo[] = [];
  for (let signerIndex = 0; signerIndex < signedData.signerInfos.length; signerIndex += 1) {
    signerVerifications.push(await verifySigner(signedData, signerIndex, warnings));
  }

  const mergedWarnings = mergeWarnings(warnings);
  return mergedWarnings
    ? { signerVerifications, warnings: mergedWarnings }
    : { signerVerifications };
};
