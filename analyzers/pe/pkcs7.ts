"use strict";

import {
  TAG_SEQUENCE,
  TAG_SET,
  TAG_OID,
  TAG_INTEGER,
  readDerElement,
  decodeOid,
  type DerElement
} from "./der.js";
import { describeOid, SPC_INDIRECT_DATA_OID } from "./pkcs7-oids.js";
import { parseCertificateContext, parseSignerInfos, parseSpcIndirectDataContent } from "./pkcs7-details.js";
import type { AuthenticodeInfo } from "./authenticode.js";

const parseAlgorithmSet = (bytes: Uint8Array, element: DerElement, warnings: string[]): string[] => {
  const algorithms: string[] = [];
  let pos = element.start + element.header;
  while (pos < element.end) {
    const seq = readDerElement(bytes, pos);
    if (!seq || seq.end > element.end || seq.tag !== TAG_SEQUENCE) break;
    const oid = readDerElement(bytes, seq.start + seq.header);
    if (oid?.tag === TAG_OID) {
      const decoded = decodeOid(bytes, oid.start + oid.header, oid.length);
      if (decoded) algorithms.push(describeOid(decoded) || decoded);
    }
    if (seq.end <= pos) break;
    pos = seq.end;
  }
  if (!algorithms.length) warnings.push("No digest algorithms listed.");
  return algorithms;
};

const countConstructedChildren = (bytes: Uint8Array, element: DerElement): number => {
  let pos = element.start + element.header;
  let count = 0;
  while (pos < element.end) {
    const child = readDerElement(bytes, pos);
    if (!child || child.end > element.end || child.end <= pos) break;
    count++;
    pos = child.end;
  }
  return count;
};

const parseContentInfo = (
  bytes: Uint8Array,
  element: DerElement,
  warnings: string[]
): { contentType?: string; payload?: Uint8Array } => {
  let pos = element.start + element.header;
  const oid = readDerElement(bytes, pos);
  if (!oid || oid.tag !== TAG_OID) {
    warnings.push("ContentInfo is missing contentType OID.");
    return {};
  }
  const contentType = decodeOid(bytes, oid.start + oid.header, oid.length) || undefined;
  pos = oid.end;
  const payloadEl = pos < element.end ? readDerElement(bytes, pos) : null;
  if (payloadEl && payloadEl.cls === "context" && payloadEl.tag === 0 && payloadEl.constructed) {
    const start = payloadEl.start + payloadEl.header;
    const payload = bytes.subarray(start, payloadEl.end);
    return contentType ? { contentType, payload } : { payload };
  }
  return contentType ? { contentType } : {};
};

const parseSignedData = (bytes: Uint8Array, warnings: string[]): Partial<AuthenticodeInfo> => {
  const seq = readDerElement(bytes, 0);
  if (!seq || seq.tag !== TAG_SEQUENCE) {
    warnings.push("SignedData is not a DER SEQUENCE.");
    return {};
  }
  let pos = seq.start + seq.header;
  const version = readDerElement(bytes, pos);
  if (!version || version.tag !== TAG_INTEGER) {
    warnings.push("SignedData missing version.");
    return {};
  }
  pos = version.end;
  const digestSet = readDerElement(bytes, pos);
  let digestAlgorithms: string[] | undefined;
  if (digestSet && digestSet.tag === TAG_SET) {
    digestAlgorithms = parseAlgorithmSet(bytes, digestSet, warnings);
    pos = digestSet.end;
  } else {
    warnings.push("SignedData missing digestAlgorithms SET.");
  }
  const contentInfoEl = readDerElement(bytes, pos);
  let payloadContentType: string | undefined;
  let payloadBytes: Uint8Array | undefined;
  if (contentInfoEl && contentInfoEl.tag === TAG_SEQUENCE) {
    const { contentType, payload } = parseContentInfo(bytes, contentInfoEl, warnings);
    payloadContentType = contentType;
    payloadBytes = payload;
    pos = contentInfoEl.end;
  } else {
    warnings.push("SignedData missing encapContentInfo.");
  }
  const result: Partial<AuthenticodeInfo> = {};
  if (digestAlgorithms) result.digestAlgorithms = digestAlgorithms;
  if (payloadContentType) {
    result.payloadContentType = payloadContentType;
    const name = describeOid(payloadContentType);
    if (name) result.payloadContentTypeName = name;
  }
  if (payloadContentType === SPC_INDIRECT_DATA_OID && payloadBytes?.length) {
    const spc = parseSpcIndirectDataContent(payloadBytes, warnings);
    if (spc.algorithmOid) result.fileDigestAlgorithm = spc.algorithmOid;
    if (spc.algorithmName) result.fileDigestAlgorithmName = spc.algorithmName;
    if (spc.digestHex) result.fileDigest = spc.digestHex;
  }
  let certificateCount: number | undefined;
  const maybeCerts = readDerElement(bytes, pos);
  if (maybeCerts && maybeCerts.cls === "context" && maybeCerts.tag === 0) {
    const start = maybeCerts.start + maybeCerts.header;
    const firstChild = readDerElement(bytes, start);
    certificateCount =
      firstChild && firstChild.tag === TAG_SET && firstChild.end <= maybeCerts.end
        ? countConstructedChildren(bytes, firstChild)
        : countConstructedChildren(bytes, maybeCerts);
    const certs = parseCertificateContext(bytes, maybeCerts, warnings);
    if (certs.length) result.certificates = certs;
    pos = maybeCerts.end;
  }
  const maybeCrl = readDerElement(bytes, pos);
  if (maybeCrl && maybeCrl.cls === "context" && maybeCrl.tag === 1) {
    pos = maybeCrl.end;
  }
  const signerSet = readDerElement(bytes, pos);
  let signerCount: number | undefined;
  if (signerSet && signerSet.tag === TAG_SET) {
    signerCount = countConstructedChildren(bytes, signerSet);
    const signers = parseSignerInfos(bytes, signerSet, warnings);
    if (signers.length) result.signers = signers;
  } else {
    warnings.push("SignerInfos SET missing or malformed.");
  }
  if (signerCount !== undefined) result.signerCount = signerCount;
  if (certificateCount !== undefined) result.certificateCount = certificateCount;
  return result;
};

export const decodePkcs7 = (payload: Uint8Array): AuthenticodeInfo => {
  const warnings: string[] = [];
  const top = readDerElement(payload, 0);
  if (!top || top.tag !== TAG_SEQUENCE) {
    return { format: "pkcs7", warnings: ["Certificate blob is not DER encoded."] };
  }
  const { contentType, payload: inner } = parseContentInfo(payload, top, warnings);
  const info: AuthenticodeInfo = { format: "pkcs7" };
  if (contentType) {
    info.contentType = contentType;
    const contentTypeName = describeOid(contentType);
    if (contentTypeName) info.contentTypeName = contentTypeName;
  }
  if (contentType !== "1.2.840.113549.1.7.2") {
    if (contentType) warnings.push(`Content type ${contentType} is not SignedData.`);
    return warnings.length ? { ...info, warnings } : info;
  }
  if (!inner?.length) {
    warnings.push("SignedData payload missing.");
    return { ...info, warnings };
  }
  const signed = parseSignedData(inner, warnings);
  return warnings.length ? { ...info, ...signed, warnings } : { ...info, ...signed };
};
