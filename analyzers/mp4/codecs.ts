"use strict";

import type { Mp4CodecDetails } from "./types.js";

const describeAvcProfile = (profileIdc: number | null): string | null => {
  if (profileIdc == null) return null;
  if (profileIdc === 66) return "Baseline";
  if (profileIdc === 77) return "Main";
  if (profileIdc === 88) return "Extended";
  if (profileIdc === 100) return "High";
  if (profileIdc === 110) return "High 10";
  if (profileIdc === 122) return "High 4:2:2";
  if (profileIdc === 144) return "High 4:4:4";
  return `Profile ${profileIdc}`;
};

const describeHevcProfile = (profileIdc: number | null): string | null => {
  if (profileIdc == null) return null;
  if (profileIdc === 1) return "Main";
  if (profileIdc === 2) return "Main 10";
  if (profileIdc === 3) return "Main Still Picture";
  if (profileIdc === 4) return "Rext";
  return `Profile ${profileIdc}`;
};

export const parsePasp = (view: DataView, start: number, size: number): string | null => {
  if (size < 8) return null;
  const hSpacing = view.getUint32(start, false);
  const vSpacing = view.getUint32(start + 4, false);
  if (hSpacing === 0 || vSpacing === 0) return null;
  return `${hSpacing}:${vSpacing}`;
};

export const readAvcC = (view: DataView, start: number, size: number, format: string): Mp4CodecDetails => {
  const profileIdc = size >= 2 ? view.getUint8(start + 1) : null;
  const compat = size >= 3 ? view.getUint8(start + 2) : null;
  const levelIdc = size >= 4 ? view.getUint8(start + 3) : null;
  const codecString =
    profileIdc != null && compat != null && levelIdc != null
      ? `${format}.${profileIdc.toString(16).padStart(2, "0")}${compat
          .toString(16)
          .padStart(2, "0")}${levelIdc.toString(16).padStart(2, "0")}`
      : null;
  return {
    format,
    codecString,
    profile: describeAvcProfile(profileIdc),
    level: levelIdc != null ? `Level ${Math.round(levelIdc / 10)}.${levelIdc % 10}` : null,
    description: null,
    width: null,
    height: null,
    pixelAspectRatio: null,
    channels: null,
    sampleRate: null,
    bitDepth: null,
    bitrate: null,
    avc: {
      profileIdc,
      profileCompatibility: compat ?? null,
      levelIdc
    }
  };
};

export const readHvcC = (view: DataView, start: number, size: number, format: string): Mp4CodecDetails => {
  if (size < 13) {
    return {
      format,
      codecString: null,
      profile: null,
      level: null,
      description: null,
      width: null,
      height: null,
      pixelAspectRatio: null,
      channels: null,
      sampleRate: null,
      bitDepth: null,
      bitrate: null,
      hevc: { profileIdc: null, tierFlag: null, levelIdc: null }
    };
  }
  const profileByte = view.getUint8(start + 1);
  const tierFlag = (profileByte & 0x20) >> 5;
  const profileIdc = profileByte & 0x1f;
  const levelIdc = view.getUint8(start + 12);
  const codecString =
    levelIdc != null && profileIdc != null ? `${format}.${profileIdc}.${tierFlag ? "H" : "L"}${levelIdc}` : null;
  return {
    format,
    codecString,
    profile: describeHevcProfile(profileIdc),
    level: levelIdc != null ? `Level ${levelIdc / 30}` : null,
    description: null,
    width: null,
    height: null,
    pixelAspectRatio: null,
    channels: null,
    sampleRate: null,
    bitDepth: null,
    bitrate: null,
    hevc: { profileIdc, tierFlag, levelIdc }
  };
};

export const readAv1C = (view: DataView, start: number, size: number, format: string): Mp4CodecDetails => {
  if (size < 4) {
    return {
      format,
      codecString: null,
      profile: null,
      level: null,
      description: null,
      width: null,
      height: null,
      pixelAspectRatio: null,
      channels: null,
      sampleRate: null,
      bitDepth: null,
      bitrate: null,
      av1: { profile: null, level: null, bitDepth: null }
    };
  }
  const byte0 = view.getUint8(start);
  const profile = (byte0 & 0x30) >> 4;
  const level = view.getUint8(start + 1) & 0x1f;
  const seqProfile = view.getUint8(start + 1);
  const seqLevel = seqProfile & 0x1f;
  const configByte = view.getUint8(start + 2);
  const highBitDepth = (configByte & 0x40) !== 0;
  const twelveBit = (configByte & 0x10) !== 0;
  const bitDepth = twelveBit ? 12 : highBitDepth ? 10 : 8;
  const codecString = `${format}.${profile}.${seqLevel}`;
  return {
    format,
    codecString,
    profile: `Profile ${profile}`,
    level: `Level ${level}`,
    description: null,
    width: null,
    height: null,
    pixelAspectRatio: null,
    channels: null,
    sampleRate: null,
    bitDepth,
    bitrate: null,
    av1: { profile, level, bitDepth }
  };
};

export const readVpcc = (view: DataView, start: number, size: number, format: string): Mp4CodecDetails => {
  if (size < 4) {
    return {
      format,
      codecString: null,
      profile: null,
      level: null,
      description: null,
      width: null,
      height: null,
      pixelAspectRatio: null,
      channels: null,
      sampleRate: null,
      bitDepth: null,
      bitrate: null,
      vp9: { profile: null, level: null, bitDepth: null }
    };
  }
  const profile = view.getUint8(start);
  const level = view.getUint8(start + 1);
  const bitDepth = view.getUint8(start + 2);
  const codecString = `${format}.0${profile}.${level}`;
  return {
    format,
    codecString,
    profile: `Profile ${profile}`,
    level: `Level ${level}`,
    description: null,
    width: null,
    height: null,
    pixelAspectRatio: null,
    channels: null,
    sampleRate: null,
    bitDepth,
    bitrate: null,
    vp9: { profile, level, bitDepth }
  };
};
