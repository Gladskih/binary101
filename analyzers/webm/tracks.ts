"use strict";

import {
  VIDEO_ID,
  AUDIO_ID,
  MAX_TRACKS_BYTES,
  TRACK_ENTRY_ID
} from "./constants.js";
import { clampReadLength, readElementHeader, readUnsigned, readFloat, readUtf8 } from "./ebml.js";
import type { EbmlElementHeader } from "./ebml.js";
import type { Issues, WebmTrack, WebmTrackAudio, WebmTrackVideo } from "./types.js";

const parseVideo = (
  dv: DataView,
  offset: number,
  size: number,
  absoluteOffset: number,
  issues: Issues
): WebmTrackVideo => {
  const video: WebmTrackVideo = {
    pixelWidth: null,
    pixelHeight: null,
    displayWidth: null,
    displayHeight: null,
    stereoMode: null,
    alphaMode: null
  };
  const pixelCrop = {
    top: null as number | null,
    bottom: null as number | null,
    left: null as number | null,
    right: null as number | null
  };
  let cursor = 0;
  const limit = Math.min(size, dv.byteLength - offset);
  while (cursor < limit) {
    const header = readElementHeader(dv, offset + cursor, absoluteOffset + cursor, issues);
    if (!header || header.headerSize === 0) break;
    const dataStart = offset + cursor + header.headerSize;
    const available = Math.min(header.size ?? 0, limit - (cursor + header.headerSize));
    if (header.id === 0xb0 && available > 0) {
      const value = readUnsigned(dv, dataStart, available, issues, "PixelWidth");
      video.pixelWidth = value != null ? Number(value) : null;
    } else if (header.id === 0xba && available > 0) {
      const value = readUnsigned(dv, dataStart, available, issues, "PixelHeight");
      video.pixelHeight = value != null ? Number(value) : null;
    } else if (header.id === 0x54b0 && available > 0) {
      const value = readUnsigned(dv, dataStart, available, issues, "DisplayWidth");
      video.displayWidth = value != null ? Number(value) : null;
    } else if (header.id === 0x54ba && available > 0) {
      const value = readUnsigned(dv, dataStart, available, issues, "DisplayHeight");
      video.displayHeight = value != null ? Number(value) : null;
    } else if (header.id === 0x53b8 && available > 0) {
      const value = readUnsigned(dv, dataStart, available, issues, "StereoMode");
      video.stereoMode = value != null ? Number(value) : null;
    } else if (header.id === 0x53c0 && available > 0) {
      const value = readUnsigned(dv, dataStart, available, issues, "AlphaMode");
      video.alphaMode = value != null ? Number(value) : null;
    } else if (header.id === 0x54aa && available > 0) {
      const value = readUnsigned(dv, dataStart, available, issues, "PixelCropBottom");
      pixelCrop.bottom = value != null ? Number(value) : null;
    } else if (header.id === 0x54bb && available > 0) {
      const value = readUnsigned(dv, dataStart, available, issues, "PixelCropTop");
      pixelCrop.top = value != null ? Number(value) : null;
    } else if (header.id === 0x54cc && available > 0) {
      const value = readUnsigned(dv, dataStart, available, issues, "PixelCropLeft");
      pixelCrop.left = value != null ? Number(value) : null;
    } else if (header.id === 0x54dd && available > 0) {
      const value = readUnsigned(dv, dataStart, available, issues, "PixelCropRight");
      pixelCrop.right = value != null ? Number(value) : null;
    }
    if (header.size == null) break;
    cursor += header.headerSize + header.size;
  }
  if (pixelCrop.top !== null || pixelCrop.bottom !== null || pixelCrop.left !== null || pixelCrop.right !== null) {
    video.pixelCrop = pixelCrop;
  }
  return video;
};

const parseAudio = (
  dv: DataView,
  offset: number,
  size: number,
  absoluteOffset: number,
  issues: Issues
): WebmTrackAudio => {
  const audio: WebmTrackAudio = {
    samplingFrequency: null,
    outputSamplingFrequency: null,
    channels: null,
    bitDepth: null
  };
  let cursor = 0;
  const limit = Math.min(size, dv.byteLength - offset);
  while (cursor < limit) {
    const header = readElementHeader(dv, offset + cursor, absoluteOffset + cursor, issues);
    if (!header || header.headerSize === 0) break;
    const dataStart = offset + cursor + header.headerSize;
    const available = Math.min(header.size ?? 0, limit - (cursor + header.headerSize));
    if (header.id === 0xb5 && available > 0) {
      audio.samplingFrequency = readFloat(dv, dataStart, available, issues, "SamplingFrequency");
    } else if (header.id === 0x78b5 && available > 0) {
      audio.outputSamplingFrequency = readFloat(dv, dataStart, available, issues, "OutputSamplingFrequency");
    } else if (header.id === 0x9f && available > 0) {
      const value = readUnsigned(dv, dataStart, available, issues, "Channels");
      audio.channels = value != null ? Number(value) : null;
    } else if (header.id === 0x6264 && available > 0) {
      const value = readUnsigned(dv, dataStart, available, issues, "BitDepth");
      audio.bitDepth = value != null ? Number(value) : null;
    }
    if (header.size == null) break;
    cursor += header.headerSize + header.size;
  }
  return audio;
};

const describeTrackType = (trackType: number | null): string => {
  if (trackType === 1) return "Video";
  if (trackType === 2) return "Audio";
  if (trackType === 3) return "Complex";
  if (trackType === 0x10) return "Logo";
  if (trackType === 0x11) return "Subtitle";
  if (trackType === 0x12) return "Buttons";
  if (trackType === 0x20) return "Metadata";
  return "Unknown";
};

export const parseTrackEntry = (
  dv: DataView,
  offset: number,
  size: number,
  absoluteOffset: number,
  issues: Issues
): WebmTrack => {
  const track: WebmTrack = {
    trackNumber: null,
    trackUid: null,
    trackType: null,
    trackTypeLabel: "Unknown",
    name: null,
    language: null,
    codecId: null,
    codecName: null,
    defaultDuration: null,
    defaultDurationFps: null,
    codecPrivateSize: null,
    flagEnabled: null,
    flagDefault: null,
    flagForced: null,
    flagLacing: null,
    video: null,
    audio: null
  };
  let cursor = 0;
  const limit = Math.min(size, dv.byteLength - offset);
  while (cursor < limit) {
    const header = readElementHeader(dv, offset + cursor, absoluteOffset + cursor, issues);
    if (!header || header.headerSize === 0) break;
    const dataStart = offset + cursor + header.headerSize;
    const available = Math.min(header.size ?? 0, limit - (cursor + header.headerSize));
    if (header.id === 0xd7 && available > 0) {
      const value = readUnsigned(dv, dataStart, available, issues, "TrackNumber");
      track.trackNumber = value != null ? Number(value) : null;
    } else if (header.id === 0x73c5 && available > 0) {
      const value = readUnsigned(dv, dataStart, available, issues, "TrackUID");
      if (value != null) {
        track.trackUid = value > BigInt(Number.MAX_SAFE_INTEGER) ? value.toString() : Number(value);
      }
    } else if (header.id === 0x83 && available > 0) {
      const value = readUnsigned(dv, dataStart, available, issues, "TrackType");
      track.trackType = value != null ? Number(value) : null;
      track.trackTypeLabel = describeTrackType(track.trackType);
    } else if (header.id === 0x86 && available > 0) {
      track.codecId = readUtf8(dv, dataStart, available);
    } else if (header.id === 0x258688 && available > 0) {
      track.codecName = readUtf8(dv, dataStart, available);
    } else if (header.id === 0x536e && available > 0) {
      track.name = readUtf8(dv, dataStart, available);
    } else if (header.id === 0x22b59c && available > 0) {
      track.language = readUtf8(dv, dataStart, available);
    } else if (header.id === 0x23e383 && available > 0) {
      const value = readUnsigned(dv, dataStart, available, issues, "DefaultDuration");
      if (value != null) {
        let numeric: number | null = null;
        const maxSafe = BigInt(Number.MAX_SAFE_INTEGER);
        if (value > maxSafe) {
          if (header.size != null && header.size <= 8) {
            numeric = Number(value & 0xffffffffn);
            issues.push("DefaultDuration is larger than safe range; using low 32 bits.");
          } else {
            issues.push("DefaultDuration is too large to represent precisely.");
          }
        } else {
          numeric = Number(value);
        }
        track.defaultDuration = numeric;
        if (numeric && numeric > 0) {
          track.defaultDurationFps = Math.round((1e9 / numeric) * 100) / 100;
        }
      }
    } else if (header.id === 0xb9 && available > 0) {
      const value = readUnsigned(dv, dataStart, available, issues, "FlagEnabled");
      track.flagEnabled = value != null ? Number(value) !== 0 : null;
    } else if (header.id === 0x88 && available > 0) {
      const value = readUnsigned(dv, dataStart, available, issues, "FlagDefault");
      track.flagDefault = value != null ? Number(value) !== 0 : null;
    } else if (header.id === 0x55aa && available > 0) {
      const value = readUnsigned(dv, dataStart, available, issues, "FlagForced");
      track.flagForced = value != null ? Number(value) !== 0 : null;
    } else if (header.id === 0x9c && available > 0) {
      const value = readUnsigned(dv, dataStart, available, issues, "FlagLacing");
      track.flagLacing = value != null ? Number(value) !== 0 : null;
    } else if (header.id === 0x63a2) {
      track.codecPrivateSize = header.size;
    } else if (header.id === VIDEO_ID && header.size != null) {
      track.video = parseVideo(dv, dataStart, header.size, header.dataOffset, issues);
    } else if (header.id === AUDIO_ID && header.size != null) {
      track.audio = parseAudio(dv, dataStart, header.size, header.dataOffset, issues);
    }
    if (header.size == null) break;
    cursor += header.headerSize + header.size;
  }
  if (!track.language) {
    track.language = "und";
    track.languageDefaulted = true;
  }
  return track;
};

export const parseTracks = async (
  file: File,
  tracksHeader: EbmlElementHeader,
  issues: Issues
): Promise<WebmTrack[]> => {
  const { length, truncated } = clampReadLength(
    file.size,
    tracksHeader.dataOffset,
    tracksHeader.size,
    MAX_TRACKS_BYTES
  );
  const dv = new DataView(await file.slice(tracksHeader.dataOffset, tracksHeader.dataOffset + length).arrayBuffer());
  const limit = tracksHeader.size != null ? Math.min(tracksHeader.size, dv.byteLength) : dv.byteLength;
  const tracks: WebmTrack[] = [];
  let cursor = 0;
  while (cursor < limit) {
    const header = readElementHeader(dv, cursor, tracksHeader.dataOffset + cursor, issues);
    if (!header || header.headerSize === 0) break;
    if (header.id === TRACK_ENTRY_ID && header.size != null) {
      const dataStart = cursor + header.headerSize;
      const available = Math.min(header.size, limit - dataStart);
      const track = parseTrackEntry(
        dv,
        dataStart,
        available,
        tracksHeader.dataOffset + dataStart,
        issues
      );
      tracks.push(track);
    }
    if (header.size == null) break;
    cursor += header.headerSize + (header.size ?? 0);
  }
  if (truncated) issues.push("Tracks section is truncated; some tracks may be missing.");
  return tracks;
};
