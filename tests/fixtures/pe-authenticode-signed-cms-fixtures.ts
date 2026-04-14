"use strict";

import * as asn1js from "asn1js";
import {
  Attribute,
  AttributeTypeAndValue,
  Certificate,
  ContentInfo,
  EncapsulatedContentInfo,
  IssuerAndSerialNumber,
  RelativeDistinguishedNames,
  SignedAndUnsignedAttributes,
  SignedData,
  SignerInfo,
  Time
} from "../../analyzers/pe/authenticode/pkijs-runtime.js";
import { computePeAuthenticodeDigest } from "../../analyzers/pe/authenticode/verify.js";
import { createStrictAuthenticodeFixture } from "./pe-authenticode-fixtures.js";

const SHA256_OID = "2.16.840.1.101.3.4.2.1";
const COMMON_NAME_OID = "2.5.4.3";
const CMS_CONTENT_TYPE_OID = "1.2.840.113549.1.9.3";
const CMS_MESSAGE_DIGEST_OID = "1.2.840.113549.1.9.4";
const CMS_SIGNING_TIME_OID = "1.2.840.113549.1.9.5";
const SPC_INDIRECT_DATA_OID = "1.3.6.1.4.1.311.2.1.4";

const toArrayBuffer = (bytes: Uint8Array): ArrayBuffer => {
  const out = new Uint8Array(bytes.byteLength);
  out.set(bytes);
  return out.buffer;
};

const hexToBytes = (hex: string): Uint8Array =>
  Uint8Array.from(
    Array.from({ length: Math.floor(hex.length / 2) }, (_, index) =>
      Number.parseInt(hex.slice(index * 2, index * 2 + 2), 16)
    )
  );

const createCommonName = (commonName: string): RelativeDistinguishedNames => {
  const name = new RelativeDistinguishedNames();
  name.typesAndValues.push(
    new AttributeTypeAndValue({
      type: COMMON_NAME_OID,
      value: new asn1js.Utf8String({ value: commonName })
    })
  );
  return name;
};

const createSpcIndirectData = (fileDigest: Uint8Array): ArrayBuffer =>
  new asn1js.Sequence({
    value: [
      new asn1js.Sequence({
        value: [new asn1js.ObjectIdentifier({ value: "1.2.3.4" })]
      }),
      new asn1js.Sequence({
        value: [
          new asn1js.Sequence({
            value: [
              new asn1js.ObjectIdentifier({ value: SHA256_OID }),
              new asn1js.Null()
            ]
          }),
          new asn1js.OctetString({ valueHex: toArrayBuffer(fileDigest) })
        ]
      })
    ]
  }).toBER();

const buildSignedAuthenticodeCmsPayload = async (fileDigestHex: string): Promise<Uint8Array> => {
  const keys = await crypto.subtle.generateKey(
    {
      name: "RSASSA-PKCS1-v1_5",
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: "SHA-256"
    },
    true,
    ["sign", "verify"]
  );
  const certificate = new Certificate();
  certificate.version = 2;
  certificate.serialNumber = new asn1js.Integer({ value: 1 });
  const commonName = createCommonName("Binary101 Authenticode Test");
  certificate.issuer = commonName;
  certificate.subject = commonName;
  certificate.notBefore = new Time({ value: new Date("2024-01-01T00:00:00Z") });
  certificate.notAfter = new Time({ value: new Date("2025-01-01T00:00:00Z") });
  await certificate.subjectPublicKeyInfo.importKey(keys.publicKey);
  await certificate.sign(keys.privateKey, "SHA-256");

  const spcIndirectData = createSpcIndirectData(hexToBytes(fileDigestHex));
  const messageDigest = await crypto.subtle.digest("SHA-256", spcIndirectData);
  const signedData = new SignedData({
    version: 1,
    encapContentInfo: new EncapsulatedContentInfo({
      eContentType: SPC_INDIRECT_DATA_OID,
      eContent: new asn1js.OctetString({ valueHex: spcIndirectData })
    }),
    certificates: [certificate]
  });
  signedData.signerInfos.push(
    new SignerInfo({
      version: 1,
      sid: new IssuerAndSerialNumber({
        issuer: certificate.issuer,
        serialNumber: certificate.serialNumber
      }),
      signedAttrs: new SignedAndUnsignedAttributes({
        type: 0,
        attributes: [
          new Attribute({
            type: CMS_CONTENT_TYPE_OID,
            values: [new asn1js.ObjectIdentifier({ value: SPC_INDIRECT_DATA_OID })]
          }),
          new Attribute({
            type: CMS_SIGNING_TIME_OID,
            values: [new asn1js.UTCTime({ valueDate: new Date("2024-01-01T00:00:00Z") })]
          }),
          new Attribute({
            type: CMS_MESSAGE_DIGEST_OID,
            values: [new asn1js.OctetString({ valueHex: messageDigest })]
          })
        ]
      })
    })
  );
  await signedData.sign(keys.privateKey, 0, "SHA-256");
  return new Uint8Array(
    new ContentInfo({
      contentType: ContentInfo.SIGNED_DATA,
      content: signedData.toSchema(true)
    }).toSchema().toBER()
  );
};

const buildFixture = async () => {
  const peFixture = createStrictAuthenticodeFixture();
  const digestHex = await computePeAuthenticodeDigest(
    peFixture.file,
    peFixture.core,
    peFixture.securityDir,
    "SHA-256"
  );
  if (!digestHex) {
    throw new Error("Unable to compute the synthetic PE Authenticode digest.");
  }
  return {
    ...peFixture,
    digestHex,
    payload: await buildSignedAuthenticodeCmsPayload(digestHex)
  };
};

let cachedFixturePromise: Promise<Awaited<ReturnType<typeof buildFixture>>> | undefined;

export const createSignedAuthenticodeCmsFixture = async () => {
  const fixture = await (cachedFixturePromise ??= buildFixture());
  return {
    ...fixture,
    payload: fixture.payload.slice()
  };
};
