"use strict";

import * as asn1js from "asn1js";
import {
  Attribute,
  ContentInfo,
  EncapsulatedContentInfo,
  IssuerAndSerialNumber,
  SignedAndUnsignedAttributes,
  SignedData,
  SignerInfo
} from "../../analyzers/pe/authenticode/pkijs-runtime.js";
import { computePeAuthenticodeDigest } from "../../analyzers/pe/authenticode/verify.js";
import { createStrictAuthenticodeFixture } from "./pe-authenticode-fixtures.js";
import {
  CMS_CONTENT_TYPE_OID,
  CMS_COUNTERSIGNATURE_OID,
  CMS_MESSAGE_DIGEST_OID,
  CMS_SIGNING_TIME_OID,
  CODE_SIGNING_EKU_OID,
  KEY_USAGE_DIGITAL_SIGNATURE,
  KEY_USAGE_KEY_CERT_SIGN,
  SPC_INDIRECT_DATA_OID,
  TIME_STAMPING_EKU_OID,
  createBasicConstraintsExtension,
  createCertificate,
  createCommonName,
  createExtendedKeyUsageExtension,
  createKeyUsageExtension,
  createSpcIndirectData,
  generateRsaKeyPair,
  hexToBytes,
  setEncodedSignedAttributes,
  toArrayBuffer
} from "./pe-authenticode-cms-helpers.js";

const buildSignedAuthenticodeCmsPayload = async (fileDigestHex: string): Promise<Uint8Array> => {
  const rootKeys = await generateRsaKeyPair();
  const signerKeys = await generateRsaKeyPair();
  const timestampKeys = await generateRsaKeyPair();
  const rootCertificate = await createCertificate(
    "Binary101 Root CA",
    1,
    rootKeys.publicKey,
    createCommonName("Binary101 Root CA"),
    rootKeys.privateKey,
    "2020-01-01T00:00:00Z",
    "2035-01-01T00:00:00Z",
    [createBasicConstraintsExtension(true), createKeyUsageExtension(KEY_USAGE_KEY_CERT_SIGN)]
  );
  const signerCertificate = await createCertificate(
    "Binary101 Authenticode Signer",
    2,
    signerKeys.publicKey,
    rootCertificate.subject,
    rootKeys.privateKey,
    "2023-01-01T00:00:00Z",
    "2030-01-01T00:00:00Z",
    [
      createBasicConstraintsExtension(false),
      createKeyUsageExtension(KEY_USAGE_DIGITAL_SIGNATURE),
      createExtendedKeyUsageExtension(CODE_SIGNING_EKU_OID)
    ]
  );
  const timestampCertificate = await createCertificate(
    "Binary101 Timestamp Authority",
    3,
    timestampKeys.publicKey,
    rootCertificate.subject,
    rootKeys.privateKey,
    "2023-01-01T00:00:00Z",
    "2030-01-01T00:00:00Z",
    [
      createBasicConstraintsExtension(false),
      createKeyUsageExtension(KEY_USAGE_DIGITAL_SIGNATURE),
      createExtendedKeyUsageExtension(TIME_STAMPING_EKU_OID)
    ]
  );

  const spcIndirectData = createSpcIndirectData(hexToBytes(fileDigestHex));
  const messageDigest = await crypto.subtle.digest("SHA-256", spcIndirectData);
  const signedData = new SignedData({
    version: 1,
    encapContentInfo: new EncapsulatedContentInfo({
      eContentType: SPC_INDIRECT_DATA_OID,
      eContent: new asn1js.OctetString({ valueHex: spcIndirectData })
    }),
    certificates: [signerCertificate, rootCertificate, timestampCertificate]
  });
  signedData.signerInfos.push(
    new SignerInfo({
      version: 1,
      sid: new IssuerAndSerialNumber({
        issuer: signerCertificate.issuer,
        serialNumber: signerCertificate.serialNumber
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
  await signedData.sign(signerKeys.privateKey, 0, "SHA-256");

  const signerInfo = signedData.signerInfos[0];
  if (!signerInfo) throw new Error("Signed CMS fixture is missing the primary signer.");
  const countersignatureDigest = await crypto.subtle.digest(
    "SHA-256",
    toArrayBuffer(signerInfo.signature.valueBlock.valueHexView)
  );
  const countersignedAttrs = new SignedAndUnsignedAttributes({
    type: 0,
    attributes: [
      new Attribute({
        type: CMS_SIGNING_TIME_OID,
        values: [new asn1js.UTCTime({ valueDate: new Date("2024-01-01T00:05:00Z") })]
      }),
      new Attribute({
        type: CMS_MESSAGE_DIGEST_OID,
        values: [new asn1js.OctetString({ valueHex: countersignatureDigest })]
      })
    ]
  });
  setEncodedSignedAttributes(countersignedAttrs);

  const countersignerInfo = new SignerInfo({
    version: 1,
    sid: new IssuerAndSerialNumber({
      issuer: timestampCertificate.issuer,
      serialNumber: timestampCertificate.serialNumber
    }),
    digestAlgorithm: signerInfo.digestAlgorithm,
    signedAttrs: countersignedAttrs,
    signatureAlgorithm: signerInfo.signatureAlgorithm
  });
  countersignerInfo.signature = new asn1js.OctetString({
    valueHex: await crypto.subtle.sign(
      { name: "RSASSA-PKCS1-v1_5" },
      timestampKeys.privateKey,
      countersignedAttrs.encodedValue
    )
  });
  signerInfo.unsignedAttrs = new SignedAndUnsignedAttributes({
    type: 1,
    attributes: [new Attribute({ type: CMS_COUNTERSIGNATURE_OID, values: [countersignerInfo.toSchema()] })]
  });

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
  if (!digestHex) throw new Error("Unable to compute the synthetic PE Authenticode digest.");
  return { ...peFixture, digestHex, payload: await buildSignedAuthenticodeCmsPayload(digestHex) };
};

let cachedFixturePromise: Promise<Awaited<ReturnType<typeof buildFixture>>> | undefined;

export const createSignedAuthenticodeCmsFixture = async () => {
  const fixture = await (cachedFixturePromise ??= buildFixture());
  return { ...fixture, payload: fixture.payload.slice() };
};
