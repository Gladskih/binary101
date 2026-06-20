"use strict";

import {
  concatParts,
  ebmlElement,
  ebmlUInt,
  encodeEbmlId,
  webmBlockPayload
} from "./webm-fixture-helpers.js";

// Matroska element IDs and Block flags:
// https://www.matroska.org/technical/elements.html
// https://www.matroska.org/technical/notes.html#block-structure
const MATROSKA = {
  segmentId: 0x18538067,
  infoId: 0x1549a966,
  clusterId: 0x1f43b675,
  clusterTimecodeId: 0xe7,
  simpleBlockId: 0xa3,
  blockGroupId: 0xa0,
  blockId: 0xa1,
  blockDurationId: 0x9b,
  referenceBlockId: 0xfb,
  voidId: 0xec,
  keyframeFlag: 0x80,
  fixedLacingFlag: 0x02
} as const;
const BLOCK_ENCODING = {
  bitsPerByte: 8,
  timecodeBytes: 2,
  trackVintWidths: {
    twoBytes: 2,
    threeBytes: 3
  }
} as const;
// RFC 8794 sections 6.2 and 7.1 define the unknown-size VINT and integer width.
const MAX_BYTE_VALUE = 0xff;
const EBML_ENCODING = {
  unknownSizeVint: new Uint8Array([MAX_BYTE_VALUE]),
  oneByteSizeVintMarker: 0x80,
  maxIntegerBytes: 8
} as const;

const unknownSizedElement = (id: number, payload: Uint8Array): Uint8Array =>
  concatParts([encodeEbmlId(id), EBML_ENCODING.unknownSizeVint, payload]);

const encodeTrackVint = (width: number): Uint8Array => {
  const bytes = new Uint8Array(width);
  bytes[0] = Uint8Array.BYTES_PER_ELEMENT << (BLOCK_ENCODING.bitsPerByte - width);
  bytes[width - Uint8Array.BYTES_PER_ELEMENT] = Uint8Array.BYTES_PER_ELEMENT;
  return bytes;
};

const truncatedElement = (id: number, payload: Uint8Array): Uint8Array => {
  const declaredSize = payload.byteLength + payload.byteLength;
  return concatParts([
    encodeEbmlId(id),
    // These fixtures are small enough for RFC 8794's one-byte Element Data Size VINT.
    new Uint8Array([EBML_ENCODING.oneByteSizeVintMarker | declaredSize]),
    payload
  ]);
};

export const createStreamTestSegment = (payload: Uint8Array): Uint8Array =>
  ebmlElement(MATROSKA.segmentId, payload);

export const createStreamTestCluster = (payload: Uint8Array): Uint8Array =>
  ebmlElement(MATROSKA.clusterId, payload);

export const createUnknownSizedCluster = (payload: Uint8Array): Uint8Array =>
  unknownSizedElement(MATROSKA.clusterId, payload);

export const createUnknownSizedInfo = (): Uint8Array =>
  unknownSizedElement(MATROSKA.infoId, new Uint8Array(0));

export const createClusterTimecode = (value: number): Uint8Array =>
  ebmlUInt(MATROSKA.clusterTimecodeId, value);

export const createKeyframeSimpleBlock = (
  trackNumber: number,
  timecode: number,
  payload: Uint8Array
): Uint8Array => ebmlElement(
  MATROSKA.simpleBlockId,
  createKeyframeBlockPayload(trackNumber, timecode, payload)
);

export const createSingleKeyframeClusterPayload = (): Uint8Array => concatParts([
  createClusterTimecode(0),
  createKeyframeSimpleBlock(
    Uint8Array.BYTES_PER_ELEMENT,
    0,
    new Uint8Array(0)
  )
]);

export const createKeyframeBlockPayload = (
  trackNumber: number,
  timecode: number,
  payload: Uint8Array
): Uint8Array => webmBlockPayload(
  trackNumber,
  timecode,
  MATROSKA.keyframeFlag,
  payload
);

export const createLacedBlockWithoutCount = (
  trackNumber: number,
  timecode: number
): Uint8Array => webmBlockPayload(
  trackNumber,
  timecode,
  MATROSKA.fixedLacingFlag,
  new Uint8Array(0)
);

export const createFixedLacedBlock = (
  trackNumber: number,
  timecode: number
): { payload: Uint8Array; frameCount: number } => {
  const encodedAdditionalFrameCount = Uint8Array.BYTES_PER_ELEMENT;
  return {
    payload: webmBlockPayload(
      trackNumber,
      timecode,
      MATROSKA.fixedLacingFlag,
      new Uint8Array([encodedAdditionalFrameCount])
    ),
    frameCount: encodedAdditionalFrameCount + Uint8Array.BYTES_PER_ELEMENT
  };
};

export const createBlockWithTruncatedTimecode = (): Uint8Array => {
  // A three-byte track VINT leaves only one byte where the two-byte timecode is required.
  return concatParts([
    encodeTrackVint(BLOCK_ENCODING.trackVintWidths.threeBytes),
    new Uint8Array(BLOCK_ENCODING.timecodeBytes - Uint8Array.BYTES_PER_ELEMENT)
  ]);
};

export const createBlockWithTruncatedFlags = (): Uint8Array => {
  // A two-byte track VINT and complete timecode leave no byte for Block flags.
  return concatParts([
    encodeTrackVint(BLOCK_ENCODING.trackVintWidths.twoBytes),
    new Uint8Array(BLOCK_ENCODING.timecodeBytes)
  ]);
};

export const createTruncatedSimpleBlock = (): Uint8Array => {
  const payload = createKeyframeBlockPayload(
    Uint8Array.BYTES_PER_ELEMENT,
    0,
    new Uint8Array(0)
  );
  return truncatedElement(MATROSKA.simpleBlockId, payload);
};

export const createTruncatedCluster = (payload: Uint8Array): Uint8Array =>
  truncatedElement(MATROSKA.clusterId, payload);

export const createReferencedBlockGroup = (): Uint8Array => {
  const block = ebmlElement(
    MATROSKA.blockId,
    webmBlockPayload(
      Uint8Array.BYTES_PER_ELEMENT,
      0,
      0,
      new Uint8Array([Uint8Array.BYTES_PER_ELEMENT])
    )
  );
  const reference = ebmlElement(
    MATROSKA.referenceBlockId,
    new Uint8Array([Uint8Array.BYTES_PER_ELEMENT])
  );
  const ignoredChild = ebmlElement(MATROSKA.voidId, new Uint8Array(0));
  return ebmlElement(MATROSKA.blockGroupId, concatParts([block, reference, ignoredChild]));
};

export const createBlockGroupWithEmptyBlock = (): Uint8Array =>
  ebmlElement(
    MATROSKA.blockGroupId,
    ebmlElement(MATROSKA.blockId, new Uint8Array(0))
  );

export const createEmptySimpleBlock = (): Uint8Array =>
  ebmlElement(MATROSKA.simpleBlockId, new Uint8Array(0));

export const createTimedKeyframeBlockGroup = (): {
  element: Uint8Array;
  durationTimecode: number;
} => {
  const durationTimecode = Uint8Array.BYTES_PER_ELEMENT;
  const block = ebmlElement(
    MATROSKA.blockId,
    webmBlockPayload(
      Uint8Array.BYTES_PER_ELEMENT,
      0,
      0,
      new Uint8Array(0)
    )
  );
  const duration = ebmlUInt(MATROSKA.blockDurationId, durationTimecode);
  return {
    element: ebmlElement(MATROSKA.blockGroupId, concatParts([block, duration])),
    durationTimecode
  };
};

export const createUnknownSizedBlockGroup = (): Uint8Array =>
  unknownSizedElement(MATROSKA.blockGroupId, new Uint8Array(0));

export const createBlockGroupWithUnknownSizedReference = (): Uint8Array =>
  ebmlElement(
    MATROSKA.blockGroupId,
    unknownSizedElement(MATROSKA.referenceBlockId, new Uint8Array(0))
  );

export const createBlockGroupWithUnknownSizedChild = (): Uint8Array =>
  ebmlElement(
    MATROSKA.blockGroupId,
    unknownSizedElement(MATROSKA.voidId, new Uint8Array(0))
  );

export const createUnknownSizedSimpleBlock = (): Uint8Array =>
  unknownSizedElement(MATROSKA.simpleBlockId, new Uint8Array(0));

export const createUnknownSizedClusterChild = (): Uint8Array =>
  unknownSizedElement(MATROSKA.voidId, new Uint8Array(0));

export const createEmptyClusterTimecode = (): Uint8Array =>
  ebmlElement(MATROSKA.clusterTimecodeId, new Uint8Array(0));

export const createUnsafeClusterTimecode = (): Uint8Array =>
  ebmlElement(
    MATROSKA.clusterTimecodeId,
    new Uint8Array(EBML_ENCODING.maxIntegerBytes).fill(MAX_BYTE_VALUE)
  );

export const createOversizedClusterTimecode = (): {
  element: Uint8Array;
  integerBytes: number;
} => {
  const integerBytes = EBML_ENCODING.maxIntegerBytes + Uint8Array.BYTES_PER_ELEMENT;
  return {
    element: ebmlElement(MATROSKA.clusterTimecodeId, new Uint8Array(integerBytes)),
    integerBytes
  };
};

export const createStreamTestElement = (payload: Uint8Array): Uint8Array =>
  ebmlElement(MATROSKA.voidId, payload);

export const createTruncatedElementId = (): Uint8Array =>
  encodeEbmlId(MATROSKA.segmentId).subarray(0, Uint8Array.BYTES_PER_ELEMENT);
