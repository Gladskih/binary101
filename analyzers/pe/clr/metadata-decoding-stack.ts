"use strict";

// Tasks suspend before decoding a child; their explicit stack follows the bytes in the blob.
// No JavaScript call-stack recursion or depth budget is needed for nested CLI metadata.
export type MetadataDecodingTask<Result = unknown> = Generator<MetadataDecodingTask, Result, unknown>;

export const runMetadataDecoding = <Result>(task: MetadataDecodingTask<Result>): Result => {
  const stack: MetadataDecodingTask[] = [task];
  let value: unknown;
  while (stack.length) {
    const step = stack[stack.length - 1]!.next(value);
    if (step.done) {
      stack.pop();
      value = step.value;
    } else {
      stack.push(step.value);
      value = undefined;
    }
  }
  return value as Result;
};
