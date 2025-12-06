"use strict";

import { ASF_HEADER_EXTENSION_GUID, FILETIME_EPOCH_DIFF } from "../../analyzers/asf/constants.js";

const guidBytes = (guid: string): Uint8Array => {
  const hex = guid.replace(/-/g, "");
  const data1 = hex.slice(0, 8);
  const data2 = hex.slice(8, 12);
  const data3 = hex.slice(12, 16);
  const data4 = hex.slice(16);
  const bytes = new Uint8Array(16);
  bytes[0] = Number.parseInt(data1.slice(6), 16);
  bytes[1] = Number.parseInt(data1.slice(4, 6), 16);
  bytes[2] = Number.parseInt(data1.slice(2, 4), 16);
  bytes[3] = Number.parseInt(data1.slice(0, 2), 16);
  bytes[4] = Number.parseInt(data2.slice(2), 16);
  bytes[5] = Number.parseInt(data2.slice(0, 2), 16);
  bytes[6] = Number.parseInt(data3.slice(2), 16);
  bytes[7] = Number.parseInt(data3.slice(0, 2), 16);
  for (let i = 0; i < 8; i += 1) {
    bytes[8 + i] = Number.parseInt(data4.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
};

const writeQword = (dv: DataView, offset: number, value: bigint): void => {
  dv.setUint32(offset, Number(value & 0xffffffffn), true);
  dv.setUint32(offset + 4, Number(value >> 32n), true);
};

const buildObject = (guid: string, payload: Uint8Array): Uint8Array => {
  const size = payload.length + 24;
  const buffer = new Uint8Array(size);
  buffer.set(guidBytes(guid), 0);
  const dv = new DataView(buffer.buffer);
  dv.setUint32(16, size, true);
  dv.setUint32(20, 0, true);
  buffer.set(payload, 24);
  return buffer;
};

const buildFileProperties = (): Uint8Array => {
  const payload = new Uint8Array(80);
  payload.set(guidBytes("00112233-4455-6677-8899-aabbccddeeff"), 0);
  const dv = new DataView(payload.buffer);
  const creation = FILETIME_EPOCH_DIFF + BigInt(Date.UTC(2024, 0, 2, 12, 0, 0)) * 10000n;
  writeQword(dv, 16, 0n); // file size patched later
  writeQword(dv, 24, creation);
  writeQword(dv, 32, 5n); // data packets
  writeQword(dv, 40, 50000000n); // 5s play duration
  writeQword(dv, 48, 52000000n); // send duration
  writeQword(dv, 56, 2000n); // preroll ms
  dv.setUint32(64, 0x2, true); // seekable
  dv.setUint32(68, 2048, true);
  dv.setUint32(72, 2048, true);
  dv.setUint32(76, 640000, true);
  return buildObject("8cabdca1-a947-11cf-8ee4-00c00c205365", payload);
};

const buildAudioStream = (): Uint8Array => {
  const streamType = guidBytes("f8699e40-5b4d-11cf-a8fd-00805f5c442b");
  const payload = new Uint8Array(54 + 18);
  payload.set(streamType, 0);
  // error correction GUID left zero
  const dv = new DataView(payload.buffer);
  writeQword(dv, 32, 0n); // time offset
  dv.setUint32(40, 18, true); // type-specific length
  dv.setUint32(44, 0, true); // error data length
  dv.setUint16(48, 0x0001, true); // flags stream number 1
  dv.setUint32(50, 0, true); // reserved
  dv.setUint16(54, 0x0161, true); // WMA2
  dv.setUint16(56, 2, true); // channels
  dv.setUint32(58, 44100, true); // sample rate
  dv.setUint32(62, 176400, true); // avg bytes per sec
  dv.setUint16(66, 4, true); // block align
  dv.setUint16(68, 16, true); // bits per sample
  dv.setUint16(70, 0, true); // cbSize
  return buildObject("b7dc0791-a9b7-11cf-8ee6-00c00c205365", payload);
};

const buildVideoStream = (): Uint8Array => {
  const streamType = guidBytes("bc19efc0-5b4d-11cf-a8fd-00805f5c442b");
  const payload = new Uint8Array(54 + 88);
  payload.set(streamType, 0);
  const dv = new DataView(payload.buffer);
  writeQword(dv, 32, 0n);
  dv.setUint32(40, 88, true);
  dv.setUint32(44, 0, true);
  dv.setUint16(48, 0x0002, true); // stream number 2
  dv.setUint32(50, 0, true);
  dv.setUint32(86, 500000, true); // bitrate at offset 32 within payload
  dv.setUint32(90, 0, true);
  writeQword(dv, 94, 333333n);
  dv.setUint32(102, 40, true); // bmi header size
  dv.setInt32(106, 640, true);
  dv.setInt32(110, 360, true);
  dv.setUint16(114, 1, true);
  dv.setUint16(116, 24, true);
  dv.setUint32(118, 0x33564d57, true); // WMV3
  dv.setUint32(122, 0, true);
  return buildObject("b7dc0791-a9b7-11cf-8ee6-00c00c205365", payload);
};

const buildContentDescription = (): Uint8Array => {
  const strings = ["Sample", "Author", "Copyright", "Notes", "G"];
  const encoded = strings.map(text => Buffer.from(text, "utf16le"));
  const header = new Uint8Array(10 + encoded.reduce((s, item) => s + item.length, 0));
  const dv = new DataView(header.buffer);
  let cursor = 10;
  encoded.forEach((value, index) => {
    dv.setUint16(index * 2, value.length, true);
    header.set(value, cursor);
    cursor += value.length;
  });
  return buildObject("75b22633-668e-11cf-a6d9-00aa0062ce6c", header);
};

const buildExtendedContent = (): Uint8Array => {
  const parts: number[] = [];
  const pushWord = (value: number) => { parts.push(value & 0xff, (value >> 8) & 0xff); };
  pushWord(2); // descriptor count
  const addStringDescriptor = (name: string, value: string) => {
    const nameBytes = Buffer.from(name, "utf16le");
    const valueBytes = Buffer.from(value, "utf16le");
    pushWord(nameBytes.length);
    parts.push(...nameBytes);
    pushWord(0); // type string
    pushWord(valueBytes.length);
    parts.push(...valueBytes);
  };
  addStringDescriptor("WM/AlbumTitle", "Album");
  const name = Buffer.from("WM/TrackNumber", "utf16le");
  pushWord(name.length);
  parts.push(...name);
  pushWord(3); // DWORD
  pushWord(4);
  parts.push(1, 0, 0, 0);
  return buildObject("d2d0a440-e307-11d2-97f0-00a0c95ea850", new Uint8Array(parts));
};

const buildCodecList = (): Uint8Array => {
  const reserved = guidBytes("00000000-0000-0000-0000-000000000000");
  const entries: number[] = [...reserved, 2, 0, 0, 0];
  const addEntry = (type: number, name: string, desc: string) => {
    const nameBytes = Buffer.from(name, "utf16le");
    const descBytes = Buffer.from(desc, "utf16le");
    entries.push(type, 0, nameBytes.length & 0xff, nameBytes.length >> 8, ...nameBytes);
    entries.push(descBytes.length & 0xff, descBytes.length >> 8, ...descBytes);
    entries.push(0, 0); // info length
  };
  addEntry(2, "Windows Media Audio 9.2", "WMA 2-pass");
  addEntry(1, "Windows Media Video 9", "WMV3 main profile");
  return buildObject("86d15240-311d-11d0-a3a4-00a0c90348f6", new Uint8Array(entries));
};

const buildHeaderExtension = (): Uint8Array => {
  const payload = new Uint8Array(22);
  payload.set(guidBytes(ASF_HEADER_EXTENSION_GUID), 0);
  const dv = new DataView(payload.buffer);
  dv.setUint16(16, 0x0006, true);
  dv.setUint32(18, 0, true);
  return buildObject("5fbf03b5-a92e-11cf-8ee3-00c00c205365", payload);
};

const buildDataObject = (): Uint8Array => {
  const payload = new Uint8Array(30);
  payload.set(guidBytes("00112233-4455-6677-8899-aabbccddeeff"), 0);
  const dv = new DataView(payload.buffer);
  writeQword(dv, 16, 5n);
  dv.setUint16(24, 0, true);
  payload[26] = 0xaa;
  payload[27] = 0xbb;
  payload[28] = 0xcc;
  payload[29] = 0xdd;
  return buildObject("75b22636-668e-11cf-a6d9-00aa0062ce6c", payload);
};

export const createSampleAsfFile = (): File => {
  const fileProps = buildFileProperties();
  const subObjects = [
    fileProps,
    buildAudioStream(),
    buildVideoStream(),
    buildContentDescription(),
    buildExtendedContent(),
    buildCodecList(),
    buildHeaderExtension()
  ];
  const headerPayloadLength = subObjects.reduce((sum, obj) => sum + obj.length, 0) + 6; // count + reserved bytes
  const headerPayload = new Uint8Array(headerPayloadLength);
  const hdv = new DataView(headerPayload.buffer);
  hdv.setUint32(0, subObjects.length, true);
  hdv.setUint8(4, 1);
  hdv.setUint8(5, 2);
  let cursor = 6;
  subObjects.forEach(obj => {
    headerPayload.set(obj, cursor);
    cursor += obj.length;
  });
  const headerObject = buildObject("75b22630-668e-11cf-a6d9-00aa0062ce6c", headerPayload);
  const dataObject = buildDataObject();
  const full = new Uint8Array(headerObject.length + dataObject.length);
  full.set(headerObject, 0);
  full.set(dataObject, headerObject.length);
  const totalSize = BigInt(full.length);
  const fullView = new DataView(full.buffer);
  const fileSizeOffset = 24 + 6 + 24 + 16; // header + count/res + file props header + file size field
  writeQword(fullView, fileSizeOffset, totalSize);
  return new File([full], "sample.asf", { type: "video/x-ms-wmv" });
};
