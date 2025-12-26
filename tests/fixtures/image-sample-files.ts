"use strict";

import { MockFile } from "../helpers/mock-file.js";

const fromBase64 = (base64: string): Uint8Array => new Uint8Array(Buffer.from(base64, "base64"));

export const createPngFile = () =>
  new MockFile(
    fromBase64("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/5+hHgAFgwJ/l7nnMgAAAABJRU5ErkJggg=="),
    "sample.png",
    "image/png"
  );

export const createGifFile = () =>
  new MockFile(
    fromBase64("R0lGODlhAQABAIAAAAAAAP///ywAAAAAAQABAAACAUwAOw=="),
    "sample.gif",
    "image/gif"
  );

export const createJpegFile = () =>
  new MockFile(
    fromBase64("/9j/4AAQSkZJRgABAQEAYABgAAD/2wCEAAEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQH/wAALCAABAAEBAREA/8QAFQABAQAAAAAAAAAAAAAAAAAAAAj/xAAUEAEAAAAAAAAAAAAAAAAAAAAA/9oADAMBAAIQAxAAAAH/AP/EABQQAQAAAAAAAAAAAAAAAAAAAD/2gAIAQEAAAAl/8QAFBEBAAAAAAAAAAAAAAAAAAAAAP/aAAgBAwEBPwE//8QAFBEBAAAAAAAAAAAAAAAAAAAAAP/aAAgBAgEBPwE//8QAFBABAAAAAAAAAAAAAAAAAAAAAP/aAAgBAwEBPwE//9k="),
    "sample.jpg",
    "image/jpeg"
  );

export const createWebpFile = () =>
  new MockFile(
    fromBase64("UklGRiIAAABXRUJQVlA4ICAAAAAwAQCdASoBAAEAAQAcJaQAA3AA/vuUAAA="),
    "sample.webp",
    "image/webp"
  );

export const createBmpFile = () =>
  new MockFile(
    fromBase64("Qk06AAAAAAAAADYAAAAoAAAAAQAAAAEAAAABABgAAAAAAAQAAAATCwAAEwsAAAAAAAAAAAAAAAD/AA=="),
    "sample.bmp",
    "image/bmp"
  );

export const createPngWithIhdr = () =>
  new MockFile(
    fromBase64("iVBORw0KGgoAAAANSUhEUgAAAAIAAAACCAIAAAB7GkOtAAAADUlEQVR42mNk+M9QDwADaQH4UNIAMwAAAABJRU5ErkJggg=="),
    "two-by-two.png",
    "image/png"
  );
