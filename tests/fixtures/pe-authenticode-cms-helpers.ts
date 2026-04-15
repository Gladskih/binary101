"use strict";

import * as asn1js from "asn1js";
import type { SignedAndUnsignedAttributes } from "../../analyzers/pe/authenticode/pkijs-runtime.js";
import {
  AttributeTypeAndValue,
  BasicConstraints,
  Certificate,
  ExtKeyUsage,
  Extension,
  RelativeDistinguishedNames,
  Time
} from "../../analyzers/pe/authenticode/pkijs-runtime.js";

export const SHA256_OID = "2.16.840.1.101.3.4.2.1";
export const COMMON_NAME_OID = "2.5.4.3";
export const CMS_CONTENT_TYPE_OID = "1.2.840.113549.1.9.3";
export const CMS_MESSAGE_DIGEST_OID = "1.2.840.113549.1.9.4";
export const CMS_SIGNING_TIME_OID = "1.2.840.113549.1.9.5";
export const CMS_COUNTERSIGNATURE_OID = "1.2.840.113549.1.9.6";
export const SPC_INDIRECT_DATA_OID = "1.3.6.1.4.1.311.2.1.4";
export const CODE_SIGNING_EKU_OID = "1.3.6.1.5.5.7.3.3";
export const TIME_STAMPING_EKU_OID = "1.3.6.1.5.5.7.3.8";
export const KEY_USAGE_DIGITAL_SIGNATURE = 0x80;
export const KEY_USAGE_KEY_CERT_SIGN = 0x04;

const KEY_USAGE_OID = "2.5.29.15";
const BASIC_CONSTRAINTS_OID = "2.5.29.19";
const EXTENDED_KEY_USAGE_OID = "2.5.29.37";

export const toArrayBuffer = (bytes: Uint8Array): ArrayBuffer => {
  const out = new Uint8Array(bytes.byteLength);
  out.set(bytes);
  return out.buffer;
};

export const hexToBytes = (hex: string): Uint8Array =>
  Uint8Array.from(
    Array.from({ length: Math.floor(hex.length / 2) }, (_, index) =>
      Number.parseInt(hex.slice(index * 2, index * 2 + 2), 16)
    )
  );

export const createCommonName = (commonName: string): RelativeDistinguishedNames => {
  const name = new RelativeDistinguishedNames();
  name.typesAndValues.push(
    new AttributeTypeAndValue({
      type: COMMON_NAME_OID,
      value: new asn1js.Utf8String({ value: commonName })
    })
  );
  return name;
};

export const createSpcIndirectData = (fileDigest: Uint8Array): ArrayBuffer =>
  new asn1js.Sequence({
    value: [
      new asn1js.Sequence({ value: [new asn1js.ObjectIdentifier({ value: "1.2.3.4" })] }),
      new asn1js.Sequence({
        value: [
          new asn1js.Sequence({
            value: [new asn1js.ObjectIdentifier({ value: SHA256_OID }), new asn1js.Null()]
          }),
          new asn1js.OctetString({ valueHex: toArrayBuffer(fileDigest) })
        ]
      })
    ]
  }).toBER();

export const createKeyUsageExtension = (usageByte: number): Extension => {
  const bitString = new asn1js.BitString({ valueHex: Uint8Array.of(usageByte).buffer });
  return new Extension({
    extnID: KEY_USAGE_OID,
    critical: true,
    extnValue: bitString.toBER(false),
    parsedValue: bitString
  });
};

export const createBasicConstraintsExtension = (isCa: boolean): Extension => {
  const basicConstraints = new BasicConstraints({ cA: isCa });
  return new Extension({
    extnID: BASIC_CONSTRAINTS_OID,
    critical: true,
    extnValue: basicConstraints.toSchema().toBER(false),
    parsedValue: basicConstraints
  });
};

export const createExtendedKeyUsageExtension = (purposeOid: string): Extension => {
  const extKeyUsage = new ExtKeyUsage({ keyPurposes: [purposeOid] });
  return new Extension({
    extnID: EXTENDED_KEY_USAGE_OID,
    critical: false,
    extnValue: extKeyUsage.toSchema().toBER(false),
    parsedValue: extKeyUsage
  });
};

export const setEncodedSignedAttributes = (attributes: SignedAndUnsignedAttributes): void => {
  const encodedValue = ((attributes as unknown as { toSchema(): { toBER: (encodeFlag?: boolean) => ArrayBuffer } })
    .toSchema()
    .toBER(false));
  const encodedView = new Uint8Array(encodedValue);
  encodedView[0] = 0x31;
  attributes.encodedValue = encodedValue;
};

export const createCertificate = async (
  commonName: string,
  serialNumber: number,
  publicKey: CryptoKey,
  signerName: RelativeDistinguishedNames,
  privateKey: CryptoKey,
  notBefore: string,
  notAfter: string,
  extensions: Extension[]
): Promise<Certificate> => {
  const certificate = new Certificate();
  certificate.version = 2;
  certificate.serialNumber = new asn1js.Integer({ value: serialNumber });
  certificate.issuer = signerName;
  certificate.subject = createCommonName(commonName);
  certificate.notBefore = new Time({ value: new Date(notBefore) });
  certificate.notAfter = new Time({ value: new Date(notAfter) });
  certificate.extensions = extensions;
  await certificate.subjectPublicKeyInfo.importKey(publicKey);
  await certificate.sign(privateKey, "SHA-256");
  return certificate;
};

export const generateRsaKeyPair = (): Promise<CryptoKeyPair> =>
  crypto.subtle.generateKey(
    {
      name: "RSASSA-PKCS1-v1_5",
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: "SHA-256"
    },
    true,
    ["sign", "verify"]
  ) as Promise<CryptoKeyPair>;
