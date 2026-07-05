"use strict";

import { readdir, stat } from "node:fs/promises";
import { parse, resolve } from "node:path";
import { AsyncQueue } from "./async-queue.js";

type DiscoveredFile = { path: string; size: number };
type WarningSink = { count: number; messages: string[] };

const MAX_WARNING_MESSAGES = 200;

const cleanErrorMessage = (error: unknown): string =>
  error instanceof Error ? error.message : String(error);

const recordWarning = (sink: WarningSink, path: string, error: unknown): void => {
  sink.count += 1;
  if (sink.messages.length >= MAX_WARNING_MESSAGES) return;
  sink.messages.push(`${path}: ${cleanErrorMessage(error)}`);
};

const existingDefaultRoots = async (): Promise<string[]> => {
  if (process.platform !== "win32") return [parse(process.cwd()).root || "/"];
  const roots: string[] = [];
  for (const letter of "ABCDEFGHIJKLMNOPQRSTUVWXYZ") {
    try {
      if ((await stat(`${letter}:\\`)).isDirectory()) roots.push(`${letter}:\\`);
    } catch {
      // Missing drive letters are expected on Windows hosts.
    }
  }
  return roots.length ? roots : [parse(process.cwd()).root];
};

const enqueueRoot = async (
  path: string,
  enqueueDirectory: (path: string) => Promise<void>,
  onFile: (file: DiscoveredFile) => Promise<boolean>,
  warnings: WarningSink
): Promise<void> => {
  try {
    const info = await stat(path);
    if (info.isDirectory()) {
      await enqueueDirectory(resolve(path));
      return;
    }
    if (info.isFile()) await onFile({ path: resolve(path), size: info.size });
  } catch (error) {
    recordWarning(warnings, path, error);
  }
};

const discoverDirectory = async (
  path: string,
  enqueueDirectory: (path: string) => Promise<void>,
  onFile: (file: DiscoveredFile) => Promise<boolean>,
  warnings: WarningSink
): Promise<void> => {
  try {
    const entries = await readdir(path, { withFileTypes: true });
    for (const entry of entries) {
      const fullPath = resolve(path, entry.name);
      if (entry.isDirectory()) {
        await enqueueDirectory(fullPath);
      } else if (entry.isFile() && !(await onFile({ path: fullPath, size: 0 }))) {
        break;
      }
    }
  } catch (error) {
    recordWarning(warnings, path, error);
  }
};

const discoverFiles = async (
  roots: string[],
  concurrency: number,
  onFile: (file: DiscoveredFile) => Promise<boolean>,
  warnings: WarningSink
): Promise<void> => {
  const directoryQueue = new AsyncQueue<string>();
  let pendingDirectories = 0;
  let stopped = false;
  const offerFile = async (file: DiscoveredFile): Promise<boolean> => {
    if (stopped) return false;
    const keepGoing = await onFile(file);
    if (!keepGoing) {
      stopped = true;
      directoryQueue.closeAndDiscard();
    }
    return keepGoing;
  };
  const enqueueDirectory = async (path: string): Promise<void> => {
    if (stopped) return;
    pendingDirectories += 1;
    if (!(await directoryQueue.push(path))) pendingDirectories -= 1;
  };
  const finishDirectory = (): void => {
    pendingDirectories -= 1;
    if (pendingDirectories === 0) directoryQueue.close();
  };
  await Promise.all(roots.map(root => enqueueRoot(root, enqueueDirectory, offerFile, warnings)));
  if (pendingDirectories === 0) directoryQueue.close();
  const workers = Array.from({ length: concurrency }, async () => {
    for (;;) {
      const directory = await directoryQueue.shift();
      if (!directory) return;
      await discoverDirectory(directory, enqueueDirectory, offerFile, warnings);
      finishDirectory();
    }
  });
  await Promise.all(workers);
};

export { discoverFiles, existingDefaultRoots, recordWarning };
export type { DiscoveredFile, WarningSink };
