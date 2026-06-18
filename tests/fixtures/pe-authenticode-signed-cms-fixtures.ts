"use strict";
import * as asn1js from "asn1js";
import {
  AlgorithmIdentifier,
  Attribute,
  ContentInfo,
  EncapsulatedContentInfo,
  IssuerAndSerialNumber,
  MessageImprint,
  SignedAndUnsignedAttributes,
  SignedData,
  SignerInfo,
  TSTInfo,
  id_eContentType_TSTInfo
} from "../../analyzers/pe/authenticode/pkijs-runtime.js";
import type { Certificate } from "../../analyzers/pe/authenticode/pkijs-runtime.js";
import { computePeAuthenticodeDigest } from "../../analyzers/pe/authenticode/verify.js";
import { createStrictAuthenticodeFixture } from "./pe-authenticode-fixtures.js";
import {
  AUTHENTICODE_RFC3161_TIMESTAMP_OID,
  CMS_CONTENT_TYPE_OID,
  CMS_COUNTERSIGNATURE_OID,
  CMS_MESSAGE_DIGEST_OID,
  CMS_SIGNING_TIME_OID,
  CODE_SIGNING_EKU_OID,
  KEY_USAGE_DIGITAL_SIGNATURE,
  KEY_USAGE_KEY_CERT_SIGN,
  SHA256_OID,
  SPC_INDIRECT_DATA_OID,
  TIME_STAMPING_EKU_OID,
  createBasicConstraintsExtension,
  createCertificate,
  createCommonName,
  createExtendedKeyUsageExtension,
  createKeyUsageExtension,
  createSpcIndirectData,
  generateEcKeyPair,
  generateRsaKeyPair,
  hexToBytes,
  setEncodedSignedAttributes,
  toArrayBuffer
} from "./pe-authenticode-cms-helpers.js";
const EC_PUBLIC_KEY_OID = "1.2.840.10045.2.1";
const contentTypeAttribute = (oid: string): Attribute =>
  new Attribute({ type: CMS_CONTENT_TYPE_OID, values: [new asn1js.ObjectIdentifier({ value: oid })] });
const messageDigestAttribute = (messageDigest: ArrayBuffer): Attribute =>
  new Attribute({ type: CMS_MESSAGE_DIGEST_OID, values: [new asn1js.OctetString({ valueHex: messageDigest })] });
export const encodeContentInfo = (signedData: SignedData): Uint8Array =>
  new Uint8Array(
    new ContentInfo({ contentType: ContentInfo.SIGNED_DATA, content: signedData.toSchema(true) }).toSchema().toBER()
  );
export type CertificateChain = {
  root: Certificate;
  signer: Certificate;
  timestamp: Certificate;
  rootPrivateKey: CryptoKey;
  signerPrivateKey: CryptoKey;
  timestampPrivateKey: CryptoKey;
};
export const createCertificateChain = async (): Promise<CertificateChain> => {
  const rootKeys = await generateRsaKeyPair();
  const signerKeys = await generateRsaKeyPair();
  const timestampKeys = await generateRsaKeyPair();
  const rootValidity = { notBefore: "2020-01-01T00:00:00Z", notAfter: "2035-01-01T00:00:00Z" };
  const issuedValidity = { notBefore: "2023-01-01T00:00:00Z", notAfter: "2030-01-01T00:00:00Z" };
  const rootCertificate = await createCertificate("Binary101 Root CA", 1, rootKeys.publicKey,
    createCommonName("Binary101 Root CA"), rootKeys.privateKey, rootValidity,
    [createBasicConstraintsExtension(true), createKeyUsageExtension(KEY_USAGE_KEY_CERT_SIGN)]);
  const signerCertificate = await createCertificate("Binary101 Authenticode Signer", 2, signerKeys.publicKey,
    rootCertificate.subject, rootKeys.privateKey, issuedValidity, [
      createBasicConstraintsExtension(false), createKeyUsageExtension(KEY_USAGE_DIGITAL_SIGNATURE),
      createExtendedKeyUsageExtension(CODE_SIGNING_EKU_OID)
    ]);
  const timestampCertificate = await createCertificate("Binary101 Timestamp Authority", 3, timestampKeys.publicKey,
    rootCertificate.subject, rootKeys.privateKey, issuedValidity, [
      createBasicConstraintsExtension(false), createKeyUsageExtension(KEY_USAGE_DIGITAL_SIGNATURE),
      createExtendedKeyUsageExtension(TIME_STAMPING_EKU_OID)
    ]);
  return {
    root: rootCertificate,
    signer: signerCertificate,
    timestamp: timestampCertificate,
    rootPrivateKey: rootKeys.privateKey,
    signerPrivateKey: signerKeys.privateKey,
    timestampPrivateKey: timestampKeys.privateKey
  };
};
export const createSignedData = async (
  fileDigestHex: string,
  chain: CertificateChain
): Promise<SignedData> => {
  const spcIndirectData = createSpcIndirectData(hexToBytes(fileDigestHex));
  const messageDigest = await crypto.subtle.digest("SHA-256", spcIndirectData);
  const signedData = new SignedData({
    version: 1,
    encapContentInfo: new EncapsulatedContentInfo({
      eContentType: SPC_INDIRECT_DATA_OID,
      eContent: new asn1js.OctetString({ valueHex: spcIndirectData })
    }),
    certificates: [chain.signer, chain.root, chain.timestamp]
  });
  signedData.signerInfos.push(
    new SignerInfo({
      version: 1,
      sid: new IssuerAndSerialNumber({
        issuer: chain.signer.issuer,
        serialNumber: chain.signer.serialNumber
      }),
      signedAttrs: new SignedAndUnsignedAttributes({
        type: 0,
        attributes: [
          contentTypeAttribute(SPC_INDIRECT_DATA_OID),
          new Attribute({
            type: CMS_SIGNING_TIME_OID,
            values: [new asn1js.UTCTime({ valueDate: new Date("2024-01-01T00:00:00Z") })]
          }),
          messageDigestAttribute(messageDigest)
        ]
      })
    })
  );
  await signedData.sign(chain.signerPrivateKey, 0, "SHA-256");
  return signedData;
};
const createTimestampSignedData = async (
  countersignatureDigest: ArrayBuffer,
  chain: CertificateChain
): Promise<SignedData> => {
  const timestampInfo = new TSTInfo({
    version: 1,
    policy: "1.3.6.1.4.1.311.3.3.1",
    messageImprint: new MessageImprint({
      hashAlgorithm: new AlgorithmIdentifier({
        algorithmId: SHA256_OID,
        algorithmParams: new asn1js.Null()
      }),
      hashedMessage: new asn1js.OctetString({ valueHex: countersignatureDigest })
    }),
    serialNumber: new asn1js.Integer({ value: 4 }),
    genTime: new Date("2024-01-01T00:06:00Z")
  });
  const timestampContent = new EncapsulatedContentInfo({
    eContentType: id_eContentType_TSTInfo
  });
  timestampContent.eContent = new asn1js.OctetString({
    valueHex: timestampInfo.toSchema().toBER(false)
  });
  const timestampSignedData = new SignedData({
    version: 3,
    encapContentInfo: timestampContent,
    certificates: [chain.timestamp, chain.root]
  });
  timestampSignedData.signerInfos.push(
    new SignerInfo({
      version: 1,
      sid: new IssuerAndSerialNumber({
        issuer: chain.timestamp.issuer,
        serialNumber: chain.timestamp.serialNumber
      })
    })
  );
  await timestampSignedData.sign(chain.timestampPrivateKey, 0, "SHA-256");
  return timestampSignedData;
};
const createCountersignedAttributes = (
  countersignatureDigest: ArrayBuffer
): SignedAndUnsignedAttributes => {
  const countersignedAttrs = new SignedAndUnsignedAttributes({
    type: 0,
    attributes: [
      new Attribute({
        type: CMS_SIGNING_TIME_OID,
        values: [new asn1js.UTCTime({ valueDate: new Date("2024-01-01T00:05:00Z") })]
      }),
      messageDigestAttribute(countersignatureDigest)
    ]
  });
  setEncodedSignedAttributes(countersignedAttrs);
  return countersignedAttrs;
};
const createCountersignerInfo = async (
  signerInfo: SignerInfo,
  countersignatureDigest: ArrayBuffer,
  chain: CertificateChain
): Promise<SignerInfo> => {
  const countersignedAttrs = createCountersignedAttributes(countersignatureDigest);
  const countersignerInfo = new SignerInfo({
    version: 1,
    sid: new IssuerAndSerialNumber({
      issuer: chain.timestamp.issuer,
      serialNumber: chain.timestamp.serialNumber
    }),
    digestAlgorithm: signerInfo.digestAlgorithm,
    signedAttrs: countersignedAttrs,
    signatureAlgorithm: signerInfo.signatureAlgorithm
  });
  countersignerInfo.signature = new asn1js.OctetString({
    valueHex: await crypto.subtle.sign(
      { name: "RSASSA-PKCS1-v1_5" },
      chain.timestampPrivateKey,
      countersignedAttrs.encodedValue
    )
  });
  return countersignerInfo;
};
export const addTimestampUnsignedAttributes = async (
  signerInfo: SignerInfo,
  chain: CertificateChain
): Promise<void> => {
  const countersignatureDigest = await crypto.subtle.digest(
    "SHA-256",
    toArrayBuffer(signerInfo.signature.valueBlock.valueHexView)
  );
  const timestampSignedData = await createTimestampSignedData(countersignatureDigest, chain);
  const countersignerInfo = await createCountersignerInfo(signerInfo, countersignatureDigest, chain);
  signerInfo.unsignedAttrs = new SignedAndUnsignedAttributes({
    type: 1,
    attributes: [
      new Attribute({ type: CMS_COUNTERSIGNATURE_OID, values: [countersignerInfo.toSchema()] }),
      new Attribute({
        type: AUTHENTICODE_RFC3161_TIMESTAMP_OID,
        values: [
          new ContentInfo({
            contentType: ContentInfo.SIGNED_DATA,
            content: timestampSignedData.toSchema(true)
          }).toSchema()
        ]
      })
    ]
  });
};
const buildSignedAuthenticodeCmsPayload = async (fileDigestHex: string): Promise<Uint8Array> => {
  const chain = await createCertificateChain();
  const signedData = await createSignedData(fileDigestHex, chain);
  const signerInfo = signedData.signerInfos[0];
  if (!signerInfo) throw new Error("Signed CMS fixture is missing the primary signer.");
  await addTimestampUnsignedAttributes(signerInfo, chain);
  return encodeContentInfo(signedData);
};
export const createEcPublicKeySignatureAlgorithmCmsFixture = async (): Promise<Uint8Array> => {
  const rootKeys = await generateRsaKeyPair();
  const signerKeys = await generateEcKeyPair();
  const rootCertificate = await createCertificate("Binary101 Root CA", 1, rootKeys.publicKey,
    createCommonName("Binary101 Root CA"), rootKeys.privateKey,
    { notBefore: "2020-01-01T00:00:00Z", notAfter: "2035-01-01T00:00:00Z" }, []);
  const signerCertificate = await createCertificate("Binary101 ECDSA Signer", 2, signerKeys.publicKey,
    rootCertificate.subject, rootKeys.privateKey,
    { notBefore: "2023-01-01T00:00:00Z", notAfter: "2030-01-01T00:00:00Z" }, []);
  const spcIndirectData = createSpcIndirectData(Uint8Array.of(1, 2, 3, 4));
  const messageDigest = await crypto.subtle.digest("SHA-256", spcIndirectData);
  const signedData = new SignedData({
    version: 1,
    encapContentInfo: new EncapsulatedContentInfo({
      eContentType: SPC_INDIRECT_DATA_OID,
      eContent: new asn1js.OctetString({ valueHex: spcIndirectData })
    }),
    certificates: [signerCertificate, rootCertificate]
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
          contentTypeAttribute(SPC_INDIRECT_DATA_OID),
          messageDigestAttribute(messageDigest)
        ]
      })
    })
  );
  await signedData.sign(signerKeys.privateKey, 0, "SHA-256");
  const signerInfo = signedData.signerInfos[0];
  if (!signerInfo) throw new Error("ECDSA CMS fixture is missing the primary signer.");
  signerInfo.signatureAlgorithm.algorithmId = EC_PUBLIC_KEY_OID;
  return encodeContentInfo(signedData);
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
