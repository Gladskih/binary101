import { createWriteStream, openAsBlob, type WriteStream } from "node:fs";
import { once } from "node:events";
import { parsePe } from "../../analyzers/pe/index.js";
import { parseElf } from "../../analyzers/elf/index.js";
import { GcBitReader } from "../../analyzers/native-aot/gc-bit-reader.js";
import { PeManagedGcBlobs } from "../../analyzers/pe/exception/amd64/managed-gc-blobs.js";
import { ElfNativeAotGcBlobs } from "../../analyzers/elf/native-aot-gc-blobs.js";
import type { ManagedGcInfo } from "../../analyzers/native-aot/gc-info-types.js";
import { managedGcLiveHash } from "./managed-gc-live-hash.js";

const write = async (stream: WriteStream, value: string): Promise<void> => {
  if (!stream.write(value)) await once(stream, "drain");
};

// Capture only the consumed payload prefix, without adding testing fields to parsed
// results. This validates GC decoding, not the container adapters that locate blobs.
class GcReferenceCapture {
  count = 0;
  readonly failures = new Set<string>();
  readonly touched = new Map<Uint8Array, number>();
  readonly originalBits = GcBitReader.prototype.bits;
  readonly originalPe = PeManagedGcBlobs.prototype.read;
  readonly originalElf = ElfNativeAotGcBlobs.prototype.read;
  constructor(readonly input: WriteStream, readonly expected: WriteStream) {
    const capture = this;
    GcBitReader.prototype.bits = function(width) {
      const value = capture.originalBits.call(this, width);
      capture.touched.set(this.bytes, Math.max(capture.touched.get(this.bytes) ?? 0, this.position));
      return value;
    };
    PeManagedGcBlobs.prototype.read = async function(unwind, rva) {
      capture.touched.clear();
      const info = await capture.originalPe.call(this, unwind, rva);
      await capture.record(info, this.version);
      return info;
    };
    ElfNativeAotGcBlobs.prototype.read = async function(address) {
      capture.touched.clear();
      const info = await capture.originalElf.call(this, address);
      await capture.record(info, this.version);
      return info;
    };
  }

  async record(info: ManagedGcInfo | null, version: number): Promise<void> {
    if (!info || !this.touched.size) return; // Shared blob cache hits produce no new bytes.
    if (info.warnings?.length) {
      this.failures.add(info.warnings.join());
      return;
    }
    if (this.touched.size !== 1) {
      this.failures.add("Unexpected concurrent GC payload decoding.");
      return;
    }
    const [bytes, end] = [...this.touched][0]!;
    await write(this.input, `${version} ${Buffer.from(bytes.subarray(0, Math.ceil(end / 8))).toString("hex")}\n`);
    await write(this.expected, JSON.stringify({ header: info.header, slots: info.slots,
      safePoints: info.safePoints.map(point => point.offset), interruptibleRanges: info.interruptibleRanges,
      liveHash: managedGcLiveHash(info, version) }) + "\n");
    this.count++;
  }

  restore(): void {
    GcBitReader.prototype.bits = this.originalBits;
    PeManagedGcBlobs.prototype.read = this.originalPe;
    ElfNativeAotGcBlobs.prototype.read = this.originalElf;
  }
}

/** Developer-only CLI: npx tsx tests/external/managed-gc-reference-capture.ts prefix paths... */
const captureFiles = async (prefix: string, paths: string[]): Promise<void> => {
  const input = createWriteStream(`${prefix}-input.txt`);
  const expected = createWriteStream(`${prefix}-expected.jsonl`);
  const capture = new GcReferenceCapture(input, expected);
  try {
    for (const path of paths) {
      const previousCount = capture.count;
      const file = new File([await openAsBlob(path)], "GC-reference");
      const magic = new Uint8Array(await file.slice(0, 2).arrayBuffer());
      if (magic[0] === 77) await parsePe(file);
      else await parseElf(file);
      if (capture.failures.size) throw new Error([...capture.failures].join("\n"));
      if (capture.count === previousCount) throw new Error(`No GC payloads were captured from ${path}.`);
    }
  } finally {
    capture.restore();
    input.end();
    expected.end();
    await Promise.all([once(input, "finish"), once(expected, "finish")]);
  }
};

if (process.argv[2]) await captureFiles(process.argv[2], process.argv.slice(3));
