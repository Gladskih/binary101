export interface PkijsAlgorithmIdentifier {
  algorithmId: string;
}

export interface PkijsOctetString {
  valueBlock: {
    valueHexView: Uint8Array;
  };
}

export interface PkijsInteger {
  isEqual(other: unknown): boolean;
}

export interface PkijsCryptoEngine {
  digest(algorithm: AlgorithmIdentifier, data: BufferSource): Promise<ArrayBuffer>;
  getAlgorithmByOID(oid: string, safety?: boolean, target?: string): object;
  verifyWithPublicKey(
    data: BufferSource,
    signature: PkijsOctetString,
    publicKeyInfo: unknown,
    signatureAlgorithm: PkijsAlgorithmIdentifier,
    shaAlgorithm?: string
  ): Promise<boolean>;
}

export class Attribute {
  type: string;
  values: unknown[];
  constructor(parameters?: unknown);
}

export class AttributeTypeAndValue {
  type: string;
  value: {
    valueBlock?: {
      value?: unknown;
    };
    toString?: () => string;
  };
  constructor(parameters?: unknown);
}

export class BasicConstraints {
  cA: boolean;
  constructor(parameters?: unknown);
  toSchema(): { toBER(encodeFlag?: boolean): ArrayBuffer };
}

export class ExtKeyUsage {
  keyPurposes: string[];
  constructor(parameters?: unknown);
  toSchema(): { toBER(encodeFlag?: boolean): ArrayBuffer };
}

export class Extension {
  extnID: string;
  critical: boolean;
  parsedValue?: unknown;
  constructor(parameters?: unknown);
}

export class RelativeDistinguishedNames {
  typesAndValues: AttributeTypeAndValue[];
  constructor(parameters?: unknown);
  isEqual(compareTo: unknown): boolean;
}

export class Time {
  value: Date;
  constructor(parameters?: unknown);
}

export class Certificate {
  tbsView: Uint8Array;
  version: number;
  serialNumber: PkijsInteger;
  issuer: RelativeDistinguishedNames;
  subject: RelativeDistinguishedNames;
  notBefore: Time;
  notAfter: Time;
  subjectPublicKeyInfo: {
    importKey(publicKey: CryptoKey): Promise<void>;
  };
  extensions?: Extension[];
  constructor(parameters?: unknown);
  getKeyHash(hashAlgorithm?: string): Promise<ArrayBuffer>;
  sign(privateKey: CryptoKey, hashAlgorithm?: string): Promise<void>;
  verify(issuerCertificate?: Certificate, crypto?: unknown): Promise<boolean>;
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
  eContentType?: string;
  eContent?: PkijsOctetString;
  constructor(parameters?: unknown);
}

export class IssuerAndSerialNumber {
  issuer: RelativeDistinguishedNames;
  serialNumber: PkijsInteger;
  constructor(parameters?: unknown);
}

export class SignedAndUnsignedAttributes {
  attributes: Attribute[];
  encodedValue: ArrayBuffer;
  constructor(parameters?: unknown);
}

export class SignerInfo {
  sid: IssuerAndSerialNumber | unknown;
  digestAlgorithm: PkijsAlgorithmIdentifier;
  signedAttrs?: SignedAndUnsignedAttributes;
  signatureAlgorithm: PkijsAlgorithmIdentifier;
  signature: PkijsOctetString;
  unsignedAttrs?: SignedAndUnsignedAttributes;
  constructor(parameters?: unknown);
  toSchema(): unknown;
}

export class SignedData {
  signerInfos: SignerInfo[];
  certificates?: unknown[];
  encapContentInfo: EncapsulatedContentInfo;
  constructor(parameters?: unknown);
  sign(
    privateKey: CryptoKey,
    signerIndex: number,
    hashAlgorithm?: string,
    data?: ArrayBuffer
  ): Promise<void>;
  toSchema(encodeFlag?: boolean): unknown;
  verify(params: {
    signer: number;
    checkChain: boolean;
    extendedMode: true;
  }): Promise<PkijsSignedDataVerifyResult>;
}

export const getCrypto: (safety?: boolean) => PkijsCryptoEngine | null;
