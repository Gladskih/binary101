"use strict";

import { readCompressedUInt } from "./metadata-heaps.js";
import { decodeMetadataUtf8 } from "./metadata-utf8.js";

export class MetadataBlobCursor {
  private offset = 0;
  private failed = false;
  constructor(private readonly bytes: Uint8Array, readonly issues: string[], readonly context: string) {}
  get remaining(): number { return this.bytes.length - this.offset; }
  fail(message: string): null {
    if (!this.failed) this.issues.push(`${this.context}: ${message}.`);
    this.failed = true;
    this.offset = this.bytes.length;
    return null;
  }
  readU8(): number | null {
    if (!this.remaining) return this.fail("blob is truncated");
    return this.bytes[this.offset++]!;
  }
  readCompressedUInt(): number | null {
    const value = readCompressedUInt(this.bytes, this.offset);
    if (!value) return this.fail("compressed integer is malformed or truncated");
    this.offset += value.size;
    return value.value;
  }
  readBytes(size: number): Uint8Array | null {
    if (!Number.isInteger(size) || size < 0 || size > this.remaining) return this.fail("byte range exceeds the blob");
    this.offset += size;
    return this.bytes.subarray(this.offset - size, this.offset);
  }
  readUtf8(): string | null {
    const size = this.readCompressedUInt();
    if (size == null) return null;
    const bytes = this.readBytes(size);
    if (!bytes) return null;
    return decodeMetadataUtf8(bytes, this.issues, this.context);
  }
  finish(): void { if (this.remaining) this.fail(`blob has ${this.remaining} trailing byte(s)`); }
}
