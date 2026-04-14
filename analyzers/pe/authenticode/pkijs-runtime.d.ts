export class Attribute {
  constructor(parameters?: unknown);
}

export class AttributeTypeAndValue {
  constructor(parameters?: unknown);
}

export class Certificate {
  version: number;
  serialNumber: unknown;
  issuer: RelativeDistinguishedNames;
  subject: RelativeDistinguishedNames;
  notBefore: Time;
  notAfter: Time;
  subjectPublicKeyInfo: { importKey(publicKey: CryptoKey): Promise<void> };
  constructor(parameters?: unknown);
  sign(privateKey: CryptoKey, hashAlgorithm?: string): Promise<void>;
}

export interface PkijsSignedDataVerifyResult {
  code?: number;
  message: string;
  signatureVerified?: boolean | null;
  signerCertificateVerified?: boolean | null;
}

export class ContentInfo {
  static SIGNED_DATA: string;
  static fromBER(raw: BufferSource): ContentInfo;
  contentType: string;
  content?: unknown;
  constructor(parameters?: { contentType?: string; content?: unknown; schema?: unknown });
  toSchema(): { toBER(): ArrayBuffer };
}

export class EncapsulatedContentInfo {
  constructor(parameters?: unknown);
}

export class IssuerAndSerialNumber {
  constructor(parameters?: unknown);
}

export class RelativeDistinguishedNames {
  typesAndValues: unknown[];
  constructor(parameters?: unknown);
}

export class SignedAndUnsignedAttributes {
  constructor(parameters?: unknown);
}

export class SignedData {
  signerInfos: SignerInfo[];
  certificates?: unknown[];
  constructor(parameters?: unknown);
  sign(privateKey: CryptoKey, signerIndex: number, hashAlgorithm?: string): Promise<void>;
  toSchema(encodeFlag?: boolean): unknown;
  verify(params: {
    signer: number;
    checkChain: boolean;
    extendedMode: true;
  }): Promise<PkijsSignedDataVerifyResult>;
}

export class SignerInfo {
  signature: { valueBlock: { valueHexView: Uint8Array } };
  constructor(parameters?: unknown);
}

export class Time {
  constructor(parameters?: unknown);
}
