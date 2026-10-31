import { requireResource } from "./reader.js";

// Frame_Header_Descriptor and Frame_Content_Size; Qt uses ZSTD_getFrameContentSize.
// https://github.com/facebook/zstd/blob/dev/doc/zstd_compression_format.md#frame_header
export const resourceZstdSize = (view: DataView): number => {
  requireResource(view.byteLength >= 5 && view.getUint32(0, true) === 0xfd2fb528,
    "Invalid Zstandard frame header");
  const descriptor = view.getUint8(4);
  requireResource((descriptor & 0x18) === 0, "Reserved Zstandard frame flags");
  const singleSegment = (descriptor & 0x20) !== 0;
  const sizeFlag = descriptor >>> 6;
  const sizeBytes = sizeFlag === 0 ? Number(singleSegment) : 2 ** sizeFlag;
  requireResource(sizeBytes !== 0, "Zstandard frame has unknown content size");
  const dictionaryFlag = descriptor & 3;
  const offset = 5 + Number(!singleSegment) + (dictionaryFlag === 0 ? 0 : 2 ** (dictionaryFlag - 1));
  requireResource(offset + sizeBytes <= view.byteLength, "Truncated Zstandard content size");
  const size = sizeBytes === 8 ? view.getBigUint64(offset, true) :
    BigInt(sizeBytes === 4 ? view.getUint32(offset, true) :
      sizeBytes === 2 ? view.getUint16(offset, true) + 256 : view.getUint8(offset));
  requireResource(size <= BigInt(Number.MAX_SAFE_INTEGER), "Zstandard content size exceeds safe integers");
  return Number(size);
};
