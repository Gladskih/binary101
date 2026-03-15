"use strict";

import assert from "node:assert/strict";
import type { ParseForUiResult } from "../../analyzers/analyzer-types.js";
import type { ZipCentralDirectoryEntry, ZipParseResult } from "../../analyzers/zip/types.js";

export const installZipEnvironment = (): {
  button: HTMLButtonElement;
  anchorRef: () => { href: string; download: string; clicked: number } | null;
  createdBlobRef: () => Blob | null;
  restore: () => void;
} => {
  const globals = globalThis as unknown as Record<string, unknown>;
  const hadHTMLElement = Object.prototype.hasOwnProperty.call(globals, "HTMLElement");
  const hadHTMLButtonElement = Object.prototype.hasOwnProperty.call(globals, "HTMLButtonElement");
  const hadDocument = Object.prototype.hasOwnProperty.call(globals, "document");
  const hadDecompressionStream = Object.prototype.hasOwnProperty.call(globals, "DecompressionStream");
  const originalHTMLElement = globals["HTMLElement"];
  const originalHTMLButtonElement = globals["HTMLButtonElement"];
  const originalDocument = globals["document"];
  const originalDecompressionStream = globals["DecompressionStream"];
  const originalCreateObjectURL = URL.createObjectURL;
  const originalRevokeObjectURL = URL.revokeObjectURL;

  class HTMLElementStub {
    getAttribute(this: {
      attributes?: Map<string, string>;
    }, name: string): string | null {
      return this.attributes?.get(name) ?? null;
    }
  }

  class HTMLButtonElementStub extends HTMLElementStub {}

  globals["HTMLElement"] = HTMLElementStub;
  globals["HTMLButtonElement"] = HTMLButtonElementStub;

  let anchor: { href: string; download: string; clicked: number; click: () => void } | null = null;
  let createdBlob: Blob | null = null;
  globals["document"] = {
    body: {
      appendChild(node: unknown) {
        return node;
      },
      removeChild(node: unknown) {
        return node;
      }
    },
    createElement(tagName: string) {
      assert.equal(tagName, "a");
      anchor = {
        href: "",
        download: "",
        clicked: 0,
        click() {
          this.clicked += 1;
        }
      };
      return anchor;
    }
  };

  URL.createObjectURL = (blob: Blob): string => {
    createdBlob = blob;
    return "blob:zip-test";
  };
  URL.revokeObjectURL = () => {};

  const button = Object.assign(new HTMLButtonElementStub() as HTMLButtonElement & {
    attributes: Map<string, string>;
  }, {
    attributes: new Map<string, string>([["data-zip-entry", "0"]]),
    textContent: "Extract",
    disabled: false
  });

  return {
    button,
    anchorRef: () => anchor,
    createdBlobRef: () => createdBlob,
    restore: () => {
      if (hadHTMLElement) {
        globals["HTMLElement"] = originalHTMLElement;
      } else {
        Reflect.deleteProperty(globals, "HTMLElement");
      }
      if (hadHTMLButtonElement) {
        globals["HTMLButtonElement"] = originalHTMLButtonElement;
      } else {
        Reflect.deleteProperty(globals, "HTMLButtonElement");
      }
      if (hadDocument) {
        globals["document"] = originalDocument;
      } else {
        Reflect.deleteProperty(globals, "document");
      }
      if (hadDecompressionStream) {
        globals["DecompressionStream"] = originalDecompressionStream;
      } else {
        Reflect.deleteProperty(globals, "DecompressionStream");
      }
      URL.createObjectURL = originalCreateObjectURL;
      URL.revokeObjectURL = originalRevokeObjectURL;
    }
  };
};

export const createZipParseResult = (entries: ZipCentralDirectoryEntry[]): ParseForUiResult => ({
  analyzer: "zip",
  parsed: {
    eocd: {
      offset: 0,
      diskNumber: 0,
      centralDirDisk: 0,
      entriesThisDisk: entries.length,
      totalEntries: entries.length,
      centralDirSize: 0,
      centralDirOffset: 0,
      comment: "",
      commentLength: 0
    },
    zip64Locator: null,
    zip64: null,
    centralDirectory: {
      offset: 0,
      size: 0,
      parsedSize: 0,
      truncated: false,
      entries
    },
    issues: []
  } satisfies ZipParseResult
});

export const createZipEntry = (
  overrides: Partial<ZipCentralDirectoryEntry> = {}
): ZipCentralDirectoryEntry => ({
  index: 0,
  fileName: "entry.bin",
  comment: "",
  compressionMethod: 0,
  compressionName: "stored",
  flags: 0,
  isUtf8: true,
  isEncrypted: false,
  usesDataDescriptor: false,
  modTimeIso: null,
  crc32: 0,
  compressedSize: 0,
  uncompressedSize: 0,
  diskNumberStart: 0,
  internalAttrs: 0,
  externalAttrs: 0,
  localHeaderOffset: 0,
  ...overrides
});

export const createDeflatedZipEntry = (
  overrides: Partial<ZipCentralDirectoryEntry> = {}
): ZipCentralDirectoryEntry =>
  createZipEntry({
    // PKZIP APPNOTE compression method 8 denotes a raw DEFLATE payload.
    compressionMethod: 8,
    compressionName: "deflate",
    ...overrides
  });
