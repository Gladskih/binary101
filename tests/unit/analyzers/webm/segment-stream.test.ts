"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";

import { scanSegmentClusters } from "../../../../analyzers/webm/segment-stream.js";
import { readElementAt } from "../../../../analyzers/webm/ebml.js";
import { createOneByteChunkedStreamFile } from "../../../helpers/chunked-stream-file.js";
import { MockFile } from "../../../helpers/mock-file.js";
import { concatParts } from "../../../fixtures/webm-fixture-helpers.js";
import {
  createBlockGroupWithUnknownSizedChild,
  createBlockGroupWithUnknownSizedReference,
  createBlockGroupWithEmptyBlock,
  createEmptyClusterTimecode,
  createEmptySimpleBlock,
  createOversizedClusterTimecode,
  createReferencedBlockGroup,
  createSingleKeyframeClusterPayload,
  createStreamTestCluster,
  createStreamTestSegment,
  createTimedKeyframeBlockGroup,
  createTruncatedCluster,
  createTruncatedSimpleBlock,
  createUnknownSizedBlockGroup,
  createUnknownSizedClusterChild,
  createUnknownSizedCluster,
  createUnknownSizedInfo,
  createUnknownSizedSimpleBlock,
  createUnsafeClusterTimecode
} from "../../../fixtures/webm-stream-fixtures.js";
import type { OnClusterBlock } from "../../../../analyzers/webm/cluster-block.js";

const createSegmentFile = (payload: Uint8Array): MockFile =>
  new MockFile(createStreamTestSegment(payload), "stream-segment.webm", "video/webm");

class FailingStreamBlob extends Blob {
  override stream(): ReadableStream<Uint8Array<ArrayBuffer>> {
    return new ReadableStream<Uint8Array<ArrayBuffer>>({
      type: "bytes",
      pull: controller => controller.error(new Error("fixture stream failed"))
    });
  }
}

class FailingStreamFile extends MockFile {
  override slice(start?: number, end?: number, contentType?: string): Blob {
    return new FailingStreamBlob(
      [new Uint8Array(this.data.slice(start, end)).buffer],
      { type: contentType ?? "" }
    );
  }
}

const scanFixture = async (
  source: MockFile,
  onBlock: OnClusterBlock = () => undefined
) => {
  const tracked = createOneByteChunkedStreamFile(source);
  const issues: string[] = [];
  const segmentHeader = await readElementAt(tracked.file, 0, issues);
  assert.ok(segmentHeader?.size != null);
  const result = await scanSegmentClusters(
    tracked.file,
    segmentHeader,
    segmentHeader.size,
    issues,
    onBlock
  );
  return {
    issues,
    result,
    streamSizes: tracked.streamSizes,
    expectedStreamSize: segmentHeader.size
  };
};

void test("scanSegmentClusters continues after an unknown-sized Cluster", async () => {
  const clusterPayload = createSingleKeyframeClusterPayload();
  const clusters = [
    createUnknownSizedCluster(clusterPayload),
    createStreamTestCluster(clusterPayload)
  ];

  const scanned = await scanFixture(createSegmentFile(concatParts(clusters)));

  assert.strictEqual(scanned.result.clusterCount, clusters.length);
  assert.strictEqual(scanned.result.blockCount, clusters.length);
  assert.strictEqual(scanned.result.keyframeCount, clusters.length);
  assert.deepEqual(scanned.issues, []);
  assert.deepEqual(scanned.streamSizes, [scanned.expectedStreamSize]);
});

void test("scanSegmentClusters warns when a Block exceeds its Cluster", async () => {
  const clusters = [createStreamTestCluster(createTruncatedSimpleBlock())];

  const scanned = await scanFixture(createSegmentFile(concatParts(clusters)));

  assert.strictEqual(scanned.result.clusterCount, clusters.length);
  assert.strictEqual(scanned.result.blockCount, clusters.length);
  assert.ok(scanned.issues.some(issue => issue.includes("SimpleBlock") && issue.includes("truncated")));
});

void test("scanSegmentClusters warns about Blocks shorter than their required headers", async () => {
  const groups = [createBlockGroupWithEmptyBlock()];
  const clusters = [
    createStreamTestCluster(concatParts(groups)),
    createStreamTestCluster(createEmptySimpleBlock())
  ];

  const scanned = await scanFixture(createSegmentFile(concatParts(clusters)));

  assert.strictEqual(scanned.result.clusterCount, clusters.length);
  assert.strictEqual(scanned.result.blockCount, groups.length);
  assert.ok(scanned.issues.some(issue => issue.includes("Block") && issue.includes("too short")));
  assert.ok(scanned.issues.some(issue => issue.includes("SimpleBlock") && issue.includes("too short")));
});

void test("scanSegmentClusters treats a referenced BlockGroup as non-keyframe", async () => {
  const groups = [createReferencedBlockGroup()];
  const clusters = [createStreamTestCluster(concatParts(groups))];

  const scanned = await scanFixture(createSegmentFile(concatParts(clusters)));

  assert.strictEqual(scanned.result.blockCount, groups.length);
  assert.strictEqual(scanned.result.keyframeCount, 0);
  assert.deepEqual(scanned.issues, []);
});

void test("scanSegmentClusters emits timing for an unreferenced BlockGroup", async () => {
  const groups = [createTimedKeyframeBlockGroup()];
  const timing: Array<{ durationTimecode: number | null; isKeyframe: boolean }> = [];
  const cluster = createStreamTestCluster(concatParts(groups.map(group => group.element)));

  const scanned = await scanFixture(
    createSegmentFile(cluster),
    value => timing.push(value)
  );

  assert.strictEqual(scanned.result.blockCount, groups.length);
  assert.strictEqual(scanned.result.keyframeCount, groups.length);
  assert.strictEqual(timing.length, groups.length);
  assert.strictEqual(timing[0]?.durationTimecode, groups[0]?.durationTimecode);
  assert.strictEqual(timing[0]?.isKeyframe, true);
  assert.deepEqual(scanned.issues, []);
});

void test("scanSegmentClusters stops at an unknown-sized non-Cluster element", async () => {
  const scanned = await scanFixture(createSegmentFile(createUnknownSizedInfo()));

  assert.strictEqual(scanned.result.clusterCount, 0);
  assert.ok(scanned.issues.some(issue => issue.includes("Top-level element") && issue.includes("unknown size")));
});

void test("scanSegmentClusters reports an oversized Cluster integer", async () => {
  const oversizedTimecode = createOversizedClusterTimecode();
  const clusters = [createStreamTestCluster(oversizedTimecode.element)];

  const scanned = await scanFixture(createSegmentFile(concatParts(clusters)));

  assert.strictEqual(scanned.result.clusterCount, clusters.length);
  assert.ok(scanned.issues.some(
    issue => issue.includes(`unsupported integer size ${oversizedTimecode.integerBytes}`)
  ));
});

void test("scanSegmentClusters rejects empty and unsafe Cluster timecodes", async () => {
  const clusterPayload = concatParts([
    createEmptyClusterTimecode(),
    createUnsafeClusterTimecode()
  ]);

  const scanned = await scanFixture(
    createSegmentFile(createStreamTestCluster(clusterPayload))
  );

  assert.ok(scanned.issues.some(issue => issue.includes("truncated or missing")));
  assert.ok(scanned.issues.some(issue => issue.includes("safe integer range")));
});

void test("scanSegmentClusters stops at an unknown-sized BlockGroup", async () => {
  const clusters = [createStreamTestCluster(createUnknownSizedBlockGroup())];
  const scanned = await scanFixture(
    createSegmentFile(concatParts(clusters))
  );

  assert.strictEqual(scanned.result.clusterCount, clusters.length);
  assert.ok(scanned.issues.some(issue => issue.includes("BlockGroup") && issue.includes("unknown size")));
});

void test("scanSegmentClusters stops at an unknown-sized SimpleBlock", async () => {
  const clusters = [createStreamTestCluster(createUnknownSizedSimpleBlock())];
  const scanned = await scanFixture(
    createSegmentFile(concatParts(clusters))
  );

  assert.strictEqual(scanned.result.clusterCount, clusters.length);
  assert.ok(scanned.issues.some(issue => issue.includes("SimpleBlock") && issue.includes("unknown size")));
});

void test("scanSegmentClusters reports a Cluster extending past its Segment", async () => {
  const clusters = [createTruncatedCluster(createSingleKeyframeClusterPayload())];

  const scanned = await scanFixture(createSegmentFile(concatParts(clusters)));

  assert.strictEqual(scanned.result.clusterCount, clusters.length);
  assert.ok(scanned.issues.some(issue => issue.includes("Cluster") && issue.includes("beyond the Segment")));
});

void test("scanSegmentClusters stops at an unknown-sized Cluster child", async () => {
  const clusters = [createStreamTestCluster(createUnknownSizedClusterChild())];

  const scanned = await scanFixture(createSegmentFile(concatParts(clusters)));

  assert.strictEqual(scanned.result.clusterCount, clusters.length);
  assert.ok(scanned.issues.some(issue => issue.includes("Cluster child") && issue.includes("unknown size")));
});

void test("scanSegmentClusters rejects an unknown-sized BlockGroup reference", async () => {
  const groups = [createBlockGroupWithUnknownSizedReference()];
  const clusters = [createStreamTestCluster(concatParts(groups))];

  const scanned = await scanFixture(createSegmentFile(concatParts(clusters)));

  assert.strictEqual(scanned.result.blockCount, 0);
  assert.ok(scanned.issues.some(issue => issue.includes("Cluster child") && issue.includes("unknown size")));
});

void test("scanSegmentClusters rejects another unknown-sized BlockGroup child", async () => {
  const groups = [createBlockGroupWithUnknownSizedChild()];
  const clusters = [createStreamTestCluster(concatParts(groups))];

  const scanned = await scanFixture(createSegmentFile(concatParts(clusters)));

  assert.strictEqual(scanned.result.blockCount, 0);
  assert.ok(scanned.issues.some(issue => issue.includes("Cluster child") && issue.includes("unknown size")));
});

void test("scanSegmentClusters converts stream failures to warnings", async () => {
  const source = createSegmentFile(createStreamTestCluster(new Uint8Array(0)));
  const file = new FailingStreamFile(source.data, source.name, source.type);
  const issues: string[] = [];
  const segmentHeader = await readElementAt(file, 0, issues);
  assert.ok(segmentHeader?.size != null);

  const scanned = await scanSegmentClusters(
    file,
    segmentHeader,
    segmentHeader.size,
    issues,
    () => undefined
  );

  assert.strictEqual(scanned.clusterCount, 0);
  assert.ok(issues.some(issue => issue.includes("fixture stream failed")));
});
