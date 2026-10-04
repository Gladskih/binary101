"use strict";

import { readCompressedUInt } from "./metadata-heaps.js";

export class SignatureCursor {
  private offset = 0;
  private depth = 0;
  private failed = false;

  constructor(
    private readonly bytes: Uint8Array,
    readonly issues: string[],
    private readonly context: string
  ) {}

  get remaining(): number { return this.bytes.length - this.offset; }

  fail(message: string): null {
    if (!this.failed) this.issues.push(`${this.context} signature ${message}.`);
    this.failed = true;
    this.offset = this.bytes.length;
    return null;
  }

  readU8(): number | null {
    if (!this.remaining) return this.fail("is truncated");
    return this.bytes[this.offset++]!;
  }

  peekU8(): number | null { return this.bytes[this.offset] ?? null; }

  readCompressedUInt(): number | null {
    const value = readCompressedUInt(this.bytes, this.offset);
    if (!value) return this.fail("has a malformed compressed integer");
    this.offset += value.size;
    return value.value;
  }

  readCompressedInt(): number | null {
    // ECMA-335 II.23.2: rotate the sign bit, then sign-extend 6, 13 or 28 payload bits.
    const value = readCompressedUInt(this.bytes, this.offset);
    if (!value) return this.fail("has a malformed compressed signed integer");
    this.offset += value.size;
    const magnitude = value.value >>> 1;
    return (value.value & 1) === 0
      ? magnitude : magnitude - 2 ** (value.size === 4 ? 28 : value.size * 7 - 1);
  }

  readCount(): number | null {
    const count = this.readCompressedUInt();
    if (count == null) return null;
    // Every encoded item occupies at least one byte; never allocate by an unchecked count.
    return count <= this.remaining ? count : this.fail("count exceeds the remaining bytes");
  }

  enterType(): boolean {
    // Local analysis budget, not a CLI format limit: bound recursive stack usage to 64 types.
    if (this.depth >= 64) {
      this.fail("exceeds the analysis nesting limit (64)");
      return false;
    }
    this.depth += 1;
    return true;
  }

  leaveType(): void { this.depth -= 1; }

  finish(): void {
    if (this.remaining) this.fail("has trailing bytes");
  }
}
