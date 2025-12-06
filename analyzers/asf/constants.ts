"use strict";

export const ASF_HEADER_GUID = "75b22630-668e-11cf-a6d9-00aa0062ce6c";
export const ASF_DATA_GUID = "75b22636-668e-11cf-a6d9-00aa0062ce6c";
export const ASF_FILE_PROPERTIES_GUID = "8cabdca1-a947-11cf-8ee4-00c00c205365";
export const ASF_STREAM_PROPERTIES_GUID = "b7dc0791-a9b7-11cf-8ee6-00c00c205365";
export const ASF_HEADER_EXTENSION_GUID = "5fbf03b5-a92e-11cf-8ee3-00c00c205365";
export const ASF_CONTENT_DESCRIPTION_GUID = "75b22633-668e-11cf-a6d9-00aa0062ce6c";
export const ASF_EXTENDED_CONTENT_DESCRIPTION_GUID = "d2d0a440-e307-11d2-97f0-00a0c95ea850";
export const ASF_CODEC_LIST_GUID = "86d15240-311d-11d0-a3a4-00a0c90348f6";
export const ASF_STREAM_BITRATE_GUID = "7bf875ce-468d-11d1-8d82-006097c9a2b2";
export const ASF_SIMPLE_INDEX_GUID = "33000890-e5b1-11cf-89f4-00a0c90349cb";
export const ASF_PADDING_GUID = "1806d474-cadf-4509-a4ba-9aabcb96aae8";

export const STREAM_TYPE_AUDIO = "f8699e40-5b4d-11cf-a8fd-00805f5c442b";
export const STREAM_TYPE_VIDEO = "bc19efc0-5b4d-11cf-a8fd-00805f5c442b";

export const HUNDRED_NS_PER_SECOND = 10000000;
export const FILETIME_EPOCH_DIFF = 116444736000000000n;
export const OBJECT_HEADER_SIZE = 24;
export const MAX_OBJECTS = 256;

export const GUID_NAMES: Record<string, string> = {
  [ASF_HEADER_GUID]: "Header object",
  [ASF_DATA_GUID]: "Data object",
  [ASF_FILE_PROPERTIES_GUID]: "File properties",
  [ASF_STREAM_PROPERTIES_GUID]: "Stream properties",
  [ASF_HEADER_EXTENSION_GUID]: "Header extension",
  [ASF_CONTENT_DESCRIPTION_GUID]: "Content description",
  [ASF_EXTENDED_CONTENT_DESCRIPTION_GUID]: "Extended content description",
  [ASF_CODEC_LIST_GUID]: "Codec list",
  [ASF_STREAM_BITRATE_GUID]: "Stream bitrate properties",
  [ASF_SIMPLE_INDEX_GUID]: "Simple index",
  [ASF_PADDING_GUID]: "Padding"
};

export const STREAM_TYPE_NAMES: Record<string, string> = {
  [STREAM_TYPE_AUDIO]: "Audio stream",
  [STREAM_TYPE_VIDEO]: "Video stream"
};

export const AUDIO_FORMAT_NAMES: Record<number, string> = {
  0x0001: "PCM (uncompressed)",
  0x0160: "Windows Media Audio 1",
  0x0161: "Windows Media Audio 2",
  0x0162: "Windows Media Audio Professional",
  0x0163: "Windows Media Audio Lossless",
  0x0164: "Windows Media Audio Voice"
};
