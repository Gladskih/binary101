"use strict";

import {
  TAG_SEQUENCE,
  TAG_SET,
  TAG_OID,
  TAG_INTEGER,
  TAG_OCTET_STRING,
  TAG_UTC_TIME,
  TAG_GENERALIZED_TIME,
  readDerElement,
  readDerChildren,
  decodeOid,
  bytesToHex,
  decodeDerString,
  parseDerTime,
  parseAlgorithmIdentifier,
  type DerElement
} from "./der.js";
import { describeOid, NAME_OID_KEYS, SIGNING_TIME_OID } from "./pkcs7-oids.js";
import type { AuthenticodeSignerInfo, X509CertificateInfo } from "./authenticode.js";

export const parseSpcIndirectDataContent = (
  payloadBytes: Uint8Array,
  warnings: string[]
): { algorithmOid?: string; algorithmName?: string; digestHex?: string } => {
  const top = readDerElement(payloadBytes, 0);
  const inner =
    top && top.tag === TAG_OCTET_STRING
      ? payloadBytes.subarray(top.start + top.header, top.end)
      : payloadBytes;
  const seq = readDerElement(inner, 0);
  if (!seq || seq.tag !== TAG_SEQUENCE) return {};
  const digestInfo = readDerChildren(inner, seq)[1];
  if (!digestInfo || digestInfo.tag !== TAG_SEQUENCE) return {};
  const digestChildren = readDerChildren(inner, digestInfo);
  const alg = parseAlgorithmIdentifier(inner, digestChildren[0], warnings, oid => describeOid(oid));
  const digestEl = digestChildren[1];
  const result: { algorithmOid?: string; algorithmName?: string; digestHex?: string } = {};
  if (alg.oid) {
    result.algorithmOid = alg.oid;
    const algorithmName = alg.name || describeOid(alg.oid);
    if (algorithmName) result.algorithmName = algorithmName;
  }
  if (digestEl && digestEl.tag === TAG_OCTET_STRING) {
    result.digestHex = bytesToHex(inner.subarray(digestEl.start + digestEl.header, digestEl.end));
  }
  return result;
};

const parseName = (bytes: Uint8Array, element: DerElement, warnings: string[]): string | undefined => {
  if (element.tag !== TAG_SEQUENCE) return undefined;
  const parts: string[] = [];
  for (const rdnSet of readDerChildren(bytes, element)) {
    if (rdnSet.tag !== TAG_SET) continue;
    for (const atv of readDerChildren(bytes, rdnSet)) {
      if (atv.tag !== TAG_SEQUENCE) continue;
      const oidEl = readDerElement(bytes, atv.start + atv.header);
      if (!oidEl || oidEl.tag !== TAG_OID) continue;
      const oid = decodeOid(bytes, oidEl.start + oidEl.header, oidEl.length);
      const valueEl = readDerElement(bytes, oidEl.end);
      if (!oid || !valueEl) continue;
      const valueText = decodeDerString(bytes, valueEl);
      if (!valueText) continue;
      const key = NAME_OID_KEYS[oid] || describeOid(oid) || oid;
      parts.push(`${key}=${valueText}`);
    }
  }
  if (!parts.length) warnings.push("Certificate name has no readable attributes.");
  return parts.length ? parts.join(", ") : undefined;
};

const parseX509Certificate = (
  bytes: Uint8Array,
  element: DerElement,
  warnings: string[]
): X509CertificateInfo | null => {
  if (element.tag !== TAG_SEQUENCE) return null;
  const certChildren = readDerChildren(bytes, element);
  const tbs = certChildren[0];
  if (!tbs || tbs.tag !== TAG_SEQUENCE) return null;
  const tbsChildren = readDerChildren(bytes, tbs);
  let index = 0;
  if (tbsChildren[0]?.cls === "context" && tbsChildren[0].tag === 0) index++;
  const serialEl = tbsChildren[index++];
  index++;
  const issuerEl = tbsChildren[index++];
  const validityEl = tbsChildren[index++];
  const subjectEl = tbsChildren[index++];
  const info: X509CertificateInfo = {};
  if (serialEl?.tag === TAG_INTEGER) {
    info.serialNumber = bytesToHex(bytes.subarray(serialEl.start + serialEl.header, serialEl.end));
  }
  const issuer = issuerEl ? parseName(bytes, issuerEl, warnings) : undefined;
  if (issuer) info.issuer = issuer;
  const subject = subjectEl ? parseName(bytes, subjectEl, warnings) : undefined;
  if (subject) info.subject = subject;
  if (validityEl?.tag === TAG_SEQUENCE) {
    const times = readDerChildren(bytes, validityEl);
    const beforeEl = times[0];
    const afterEl = times[1];
    if (beforeEl && (beforeEl.tag === TAG_UTC_TIME || beforeEl.tag === TAG_GENERALIZED_TIME)) {
      const before = parseDerTime(bytes, beforeEl);
      if (before) info.notBefore = before;
    }
    if (afterEl && (afterEl.tag === TAG_UTC_TIME || afterEl.tag === TAG_GENERALIZED_TIME)) {
      const after = parseDerTime(bytes, afterEl);
      if (after) info.notAfter = after;
    }
  }
  return Object.keys(info).length ? info : null;
};

export const parseCertificateContext = (
  bytes: Uint8Array,
  element: DerElement,
  warnings: string[]
): X509CertificateInfo[] => {
  const certs: X509CertificateInfo[] = [];
  let pos = element.start + element.header;
  let iterations = 0;
  while (pos < element.end && iterations < 16) {
    const child = readDerElement(bytes, pos);
    if (!child || child.end > element.end || child.end <= pos) break;
    if (child.tag === TAG_SET) {
      for (const setChild of readDerChildren(bytes, child)) {
        if (setChild.tag !== TAG_SEQUENCE) continue;
        const info = parseX509Certificate(bytes, setChild, warnings);
        if (info) certs.push(info);
      }
    } else if (child.tag === TAG_SEQUENCE) {
      const info = parseX509Certificate(bytes, child, warnings);
      if (info) certs.push(info);
    }
    pos = child.end;
    iterations++;
  }
  return certs;
};

const parseSigningTime = (bytes: Uint8Array, signedAttrs: DerElement): string | undefined => {
  let pos = signedAttrs.start + signedAttrs.header;
  let iterations = 0;
  while (pos < signedAttrs.end && iterations < 32) {
    const attr = readDerElement(bytes, pos);
    if (!attr || attr.end > signedAttrs.end || attr.tag !== TAG_SEQUENCE) break;
    const oidEl = readDerElement(bytes, attr.start + attr.header);
    if (oidEl?.tag === TAG_OID) {
      const oidVal = decodeOid(bytes, oidEl.start + oidEl.header, oidEl.length);
      const valuesEl = readDerElement(bytes, oidEl.end);
      if (oidVal === SIGNING_TIME_OID && valuesEl?.tag === TAG_SET) {
        const timeEl = readDerElement(bytes, valuesEl.start + valuesEl.header);
        if (timeEl && (timeEl.tag === TAG_UTC_TIME || timeEl.tag === TAG_GENERALIZED_TIME)) {
          return parseDerTime(bytes, timeEl);
        }
      }
    }
    pos = attr.end;
    iterations++;
  }
  return undefined;
};

const parseSignerInfo = (
  bytes: Uint8Array,
  element: DerElement,
  warnings: string[]
): AuthenticodeSignerInfo | null => {
  if (element.tag !== TAG_SEQUENCE) return null;
  const children = readDerChildren(bytes, element);
  let index = 0;
  const versionEl = children[index++];
  if (!versionEl || versionEl.tag !== TAG_INTEGER) return null;
  const sidEl = children[index++];
  let issuer: string | undefined;
  let serialNumber: string | undefined;
  if (sidEl) {
    if (sidEl.tag === TAG_SEQUENCE) {
      const sidChildren = readDerChildren(bytes, sidEl);
      const issuerEl = sidChildren[0];
      const serialEl = sidChildren[1];
      if (issuerEl) issuer = parseName(bytes, issuerEl, warnings);
      if (serialEl?.tag === TAG_INTEGER) {
        serialNumber = bytesToHex(bytes.subarray(serialEl.start + serialEl.header, serialEl.end));
      }
    } else if (sidEl.cls === "context" && sidEl.tag === 0) {
      const keyId = readDerElement(bytes, sidEl.start + sidEl.header);
      if (keyId?.tag === TAG_OCTET_STRING) {
        serialNumber = bytesToHex(bytes.subarray(keyId.start + keyId.header, keyId.end));
      }
    }
  }
  const digestAlg = parseAlgorithmIdentifier(bytes, children[index++], warnings, oid => describeOid(oid));
  let signingTime: string | undefined;
  const maybeSignedAttrs = children[index];
  if (maybeSignedAttrs && maybeSignedAttrs.cls === "context" && maybeSignedAttrs.tag === 0) {
    signingTime = parseSigningTime(bytes, maybeSignedAttrs);
    index++;
  }
  const signatureAlg = parseAlgorithmIdentifier(bytes, children[index++], warnings, oid => describeOid(oid));
  const signer: AuthenticodeSignerInfo = {};
  if (issuer) signer.issuer = issuer;
  if (serialNumber) signer.serialNumber = serialNumber;
  if (digestAlg.oid) {
    signer.digestAlgorithm = digestAlg.oid;
    const digestName = digestAlg.name || describeOid(digestAlg.oid);
    if (digestName) signer.digestAlgorithmName = digestName;
  }
  if (signatureAlg.oid) {
    signer.signatureAlgorithm = signatureAlg.oid;
    const signatureName = signatureAlg.name || describeOid(signatureAlg.oid);
    if (signatureName) signer.signatureAlgorithmName = signatureName;
  }
  if (signingTime) signer.signingTime = signingTime;
  return Object.keys(signer).length ? signer : null;
};

export const parseSignerInfos = (
  bytes: Uint8Array,
  signerSet: DerElement,
  warnings: string[]
): AuthenticodeSignerInfo[] => {
  const signers: AuthenticodeSignerInfo[] = [];
  for (const signerEl of readDerChildren(bytes, signerSet)) {
    if (signerEl.tag !== TAG_SEQUENCE) continue;
    const signer = parseSignerInfo(bytes, signerEl, warnings);
    if (signer) signers.push(signer);
  }
  return signers;
};
