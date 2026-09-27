import * as asn1js from "asn1js";
export const createCmsDigestSignerSchema = (algorithmOid: string): asn1js.Sequence =>
  new asn1js.Sequence({ value: [
    // RFC 5652 section 5.3: version 3 and [0] IMPLICIT subjectKeyIdentifier.
    new asn1js.Integer({ value: 3 }),
    new asn1js.Primitive({ idBlock: { tagClass: 3, tagNumber: 0 }, valueHex: Uint8Array.of(0).buffer }),
    new asn1js.Sequence({ value: [new asn1js.ObjectIdentifier({ value: algorithmOid })] }),
    // RFC 8017 appendix A.1: rsaEncryption; signature bytes are incidental here.
    new asn1js.Sequence({ value: [new asn1js.ObjectIdentifier({ value: "1.2.840.113549.1.1.1" })] }),
    new asn1js.OctetString({ valueHex: Uint8Array.of(0).buffer })
  ] });

export const createCmsDigestSignedDataSchema = (
  declaredAlgorithms: readonly string[],
  signerAlgorithms: readonly string[]
): asn1js.Sequence => new asn1js.Sequence({ value: [
  new asn1js.Integer({ value: 3 }),
  new asn1js.Set({ value: declaredAlgorithms.map(algorithmOid => new asn1js.Sequence({
    value: [new asn1js.ObjectIdentifier({ value: algorithmOid })]
  })) }),
  // RFC 5652 section 4: id-data.
  new asn1js.Sequence({ value: [new asn1js.ObjectIdentifier({ value: "1.2.840.113549.1.7.1" })] }),
  new asn1js.Set({ value: signerAlgorithms.map(createCmsDigestSignerSchema) })
] });

export const encodeCmsDigestSignedData = (signedData: asn1js.Sequence): Uint8Array =>
  new Uint8Array(new asn1js.Sequence({ value: [
    // RFC 5652 section 5.1: id-signedData, wrapped in ContentInfo [0] EXPLICIT.
    new asn1js.ObjectIdentifier({ value: "1.2.840.113549.1.7.2" }),
    new asn1js.Constructed({ idBlock: { tagClass: 3, tagNumber: 0 }, value: [signedData] })
  ] }).toBER(false));

export const createCmsDigestAlgorithmFixture = (
  declaredAlgorithms: readonly string[],
  signerAlgorithms: readonly string[]
): Uint8Array => encodeCmsDigestSignedData(
  createCmsDigestSignedDataSchema(declaredAlgorithms, signerAlgorithms)
);

export const wrapCmsDigestWinCertificate = (payload: Uint8Array): Uint8Array => {
  // Microsoft PE format, "The Attribute Certificate Table": 8-byte WIN_CERTIFICATE header.
  // https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#the-attribute-certificate-table-image-only
  const bytes = new Uint8Array(payload.length + 8);
  const header = new DataView(bytes.buffer);
  header.setUint32(0, bytes.length, true);
  header.setUint16(4, 0x0200, true); // WIN_CERT_REVISION_2_0.
  header.setUint16(6, 0x0002, true); // WIN_CERT_TYPE_PKCS_SIGNED_DATA.
  bytes.set(payload, 8);
  return bytes;
};
