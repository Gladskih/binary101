"use strict";
type DerClass = "universal" | "application" | "context" | "private";
const TAG_SEQUENCE = 0x10, TAG_SET = 0x11, TAG_OID = 0x06, TAG_INTEGER = 0x02;
const CLASS_NAMES: DerClass[] = ["universal", "application", "context", "private"];
const CERT_TYPE_NAMES: Record<number, string> = {
  0x0001: "X.509 (individual)",
  0x0002: "PKCS#7 SignedData (Authenticode)",
  0x0009: "TS stack signing",
  0x000a: "PKCS#7 catalog (driver)",
  0x0ef0: "EFI PKCS1.5",
  0x0ef1: "EFI GUID",
  0x0ef2: "EFI signed data"
};
const REVISION_NAMES: Record<number, string> = {
  0x0100: "Revision 1.0",
  0x0200: "Revision 2.0"
};
const OID_NAMES: Record<string, string> = {
  "1.2.840.113549.1.7.1": "PKCS#7 data",
  "1.2.840.113549.1.7.2": "PKCS#7 signedData",
  "1.3.6.1.4.1.311.2.1.4": "SPC_INDIRECT_DATA",
  "1.2.840.113549.2.5": "md5",
  "1.3.14.3.2.26": "sha1",
  "2.16.840.1.101.3.4.2.1": "sha256",
  "2.16.840.1.101.3.4.2.2": "sha384",
  "2.16.840.1.101.3.4.2.3": "sha512",
  "2.16.840.1.101.3.4.2.4": "sha224",
  "2.16.840.1.101.3.4.2.5": "sha512/224",
  "1.2.840.113549.1.1.1": "rsaEncryption"
};
export interface AuthenticodeInfo {
  format: "pkcs7";
  contentType?: string;
  contentTypeName?: string;
  payloadContentType?: string;
  payloadContentTypeName?: string;
  digestAlgorithms?: string[];
  signerCount?: number;
  certificateCount?: number;
  warnings?: string[];
}
export interface ParsedWinCertificate {
  offset: number;
  length: number;
  availableBytes: number;
  revision: number;
  revisionName: string;
  certificateType: number;
  typeName: string;
  authenticode?: AuthenticodeInfo;
  warnings?: string[];
}
interface DerElement {
  tag: number;
  cls: DerClass;
  constructed: boolean;
  length: number;
  header: number;
  start: number;
  end: number;
}
const describeOid = (oid?: string): string | undefined => (oid ? OID_NAMES[oid] || oid : undefined);
const describeType = (type: number): string =>
  CERT_TYPE_NAMES[type] || `Type 0x${type.toString(16).padStart(4, "0")}`;
const describeRevision = (rev: number): string =>
  REVISION_NAMES[rev] || `Revision 0x${rev.toString(16).padStart(4, "0")}`;
const readDerElement = (bytes: Uint8Array, offset: number): DerElement | null => {
  if (offset >= bytes.length) return null;
  const first = bytes.at(offset);
  if (first === undefined) return null;
  const cls = CLASS_NAMES[(first & 0xc0) >> 6];
  const constructed = (first & 0x20) !== 0;
  const tag = first & 0x1f;
  if (tag === 0x1f || cls === undefined) return null; // high-tag form not expected here
  const lenByte = bytes.at(offset + 1);
  if (lenByte === undefined) return null;
  let length = 0;
  let header = 2;
  if (lenByte < 0x80) {
    length = lenByte;
  } else {
    const lenCount = lenByte & 0x7f;
    if (lenCount === 0 || lenCount > 3 || offset + 2 + lenCount > bytes.length) return null;
    for (let i = 0; i < lenCount; i++) {
      const lenVal = bytes.at(offset + 2 + i);
      if (lenVal === undefined) return null;
      length = (length << 8) | lenVal;
    }
    header += lenCount;
  }
  if (offset + header + length > bytes.length) return null;
  return { tag, cls, constructed, length, header, start: offset, end: offset + header + length };
};
const decodeOid = (bytes: Uint8Array, offset: number, length: number): string | null => {
  if (length <= 0 || offset + length > bytes.length) return null;
  const view = bytes.subarray(offset, offset + length);
  const first = view.at(0);
  if (first === undefined) return null;
  const parts = [Math.floor(first / 40), first % 40];
  let value = 0;
  for (let index = 1; index < view.length; index++) {
    const byte = view.at(index);
    if (byte === undefined) return null;
    value = (value << 7) | (byte & 0x7f);
    if ((byte & 0x80) === 0) {
      parts.push(value);
      value = 0;
    }
  }
  const last = view.at(view.length - 1);
  if (last === undefined || (last & 0x80) !== 0) return null;
  return parts.join(".");
};
const parseAlgorithmSet = (
  bytes: Uint8Array,
  element: DerElement,
  warnings: string[]
): string[] => {
  const algorithms: string[] = [];
  let pos = element.start + element.header;
  const end = element.end;
  while (pos < end) {
    const seq = readDerElement(bytes, pos);
    if (!seq || seq.end > end || seq.tag !== TAG_SEQUENCE) break;
    const oid = readDerElement(bytes, seq.start + seq.header);
    if (oid?.tag === TAG_OID) {
      const decoded = decodeOid(bytes, oid.start + oid.header, oid.length);
      if (decoded) algorithms.push(describeOid(decoded) || decoded);
    }
    if (seq.end <= pos) break; // safety against zero-length
    pos = seq.end;
  }
  if (!algorithms.length) warnings.push("No digest algorithms listed.");
  return algorithms;
};
const countConstructedChildren = (bytes: Uint8Array, element: DerElement): number => {
  let pos = element.start + element.header;
  const end = element.end;
  let count = 0;
  while (pos < end) {
    const child = readDerElement(bytes, pos);
    if (!child || child.end > end || child.end <= pos) break;
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
  const end = element.end;
  const oid = readDerElement(bytes, pos);
  if (!oid || oid.tag !== TAG_OID) {
    warnings.push("ContentInfo is missing contentType OID.");
    return {};
  }
  const contentType = decodeOid(bytes, oid.start + oid.header, oid.length) || undefined;
  pos = oid.end;
  if (pos >= end) return contentType ? { contentType } : {};
  const payloadEl = readDerElement(bytes, pos);
  if (payloadEl && payloadEl.cls === "context" && payloadEl.tag === 0 && payloadEl.constructed) {
    const start = payloadEl.start + payloadEl.header;
    const finish = payloadEl.end;
    const payload = bytes.subarray(start, finish);
    return { ...(contentType ? { contentType } : {}), payload };
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
  if (contentInfoEl && contentInfoEl.tag === TAG_SEQUENCE) {
    const { contentType } = parseContentInfo(bytes, contentInfoEl, warnings);
    payloadContentType = contentType;
    pos = contentInfoEl.end;
  } else {
    warnings.push("SignedData missing encapContentInfo.");
  }
  let certificateCount: number | undefined;
  const maybeCerts = readDerElement(bytes, pos);
  if (maybeCerts && maybeCerts.cls === "context" && maybeCerts.tag === 0) {
    const start = maybeCerts.start + maybeCerts.header;
    const firstChild = readDerElement(bytes, start);
    if (firstChild && firstChild.tag === TAG_SET && firstChild.end <= maybeCerts.end) {
      certificateCount = countConstructedChildren(bytes, firstChild);
    } else {
      certificateCount = countConstructedChildren(bytes, maybeCerts);
    }
    pos = maybeCerts.end;
  }
  const maybeCrl = readDerElement(bytes, pos);
  if (maybeCrl && maybeCrl.cls === "context" && maybeCrl.tag === 1) {
    pos = maybeCrl.end;
  }
  let signerCount: number | undefined;
  const signerSet = readDerElement(bytes, pos);
  if (signerSet && signerSet.tag === TAG_SET) {
    signerCount = countConstructedChildren(bytes, signerSet);
  } else {
    warnings.push("SignerInfos SET missing or malformed.");
  }
  const result: Partial<AuthenticodeInfo> = {};
  if (digestAlgorithms) result.digestAlgorithms = digestAlgorithms;
  if (payloadContentType) {
    result.payloadContentType = payloadContentType;
    const name = describeOid(payloadContentType);
    if (name) result.payloadContentTypeName = name;
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
export const decodeWinCertificate = (
  data: Uint8Array,
  declaredLength: number,
  offset: number
): ParsedWinCertificate => {
  const headerView = new DataView(
    data.buffer,
    data.byteOffset,
    Math.min(8, data.byteLength)
  );
  const lengthField = headerView.byteLength >= 4 ? headerView.getUint32(0, true) : 0;
  const revision = headerView.byteLength >= 6 ? headerView.getUint16(4, true) : 0;
  const certificateType = headerView.byteLength >= 8 ? headerView.getUint16(6, true) : 0;
  const warnings: string[] = [];
  if (lengthField && lengthField !== declaredLength) {
    warnings.push("Length field does not match directory entry size.");
  }
  const contentStart = Math.min(8, data.byteLength);
  const payload = data.subarray(contentStart);
  if (payload.length + contentStart < declaredLength) {
    warnings.push("Certificate data is truncated.");
  }
  let authenticode: AuthenticodeInfo | undefined;
  if (certificateType === 0x0002 && payload.length) {
    authenticode = decodePkcs7(payload);
    if (authenticode.warnings?.length) warnings.push(...authenticode.warnings);
  }
  const entry: ParsedWinCertificate = {
    offset,
    length: declaredLength,
    availableBytes: data.byteLength,
    revision,
    revisionName: describeRevision(revision),
    certificateType,
    typeName: describeType(certificateType),
    ...(authenticode ? { authenticode } : {})
  };
  if (warnings.length) entry.warnings = warnings;
  return entry;
};
