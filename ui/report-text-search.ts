export interface ReportTextMatch {
  path: readonly (string | number)[];
  value: string;
}

interface SearchPath {
  key: string | number;
  parent: SearchPath | null;
}

export const reportTextPattern = (query: string): RegExp | null => {
  const needle = query.trim();
  return needle ? new RegExp(needle.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"), "iu") : null;
};

const childEntries = function* (value: object): Generator<[string | number, unknown]> {
  if (Array.isArray(value)) {
    for (let index = 0; index < value.length; index++) yield [index, value[index]];
  } else {
    for (const key of Object.keys(value)) yield [key, Reflect.get(value, key)];
  }
};

const searchableObject = (value: unknown): value is object => {
  if (!value || typeof value !== "object" || ArrayBuffer.isView(value)) return false;
  return Array.isArray(value) || Object.getPrototypeOf(value) === Object.prototype ||
    Object.getPrototypeOf(value) === null;
};

const pathParts = (path: SearchPath | null): (string | number)[] => {
  const parts: (string | number)[] = [];
  for (let current = path; current; current = current.parent) parts.push(current.key);
  return parts.reverse();
};

const parsedText = function* (root: object): Generator<ReportTextMatch | null> {
  const seen = new WeakSet<object>([root]);
  const stack: { entries: Generator<[string | number, unknown]>; path: SearchPath | null }[] = [
    { entries: childEntries(root), path: null }
  ];
  while (stack.length) {
    const current = stack[stack.length - 1]!;
    const next = current.entries.next();
    if (next.done) { stack.pop(); continue; }
    const [key, value] = next.value;
    const path = { key, parent: current.path };
    if (typeof value === "string") yield { path: pathParts(path), value };
    else if (searchableObject(value) && !seen.has(value)) {
      seen.add(value);
      stack.push({ entries: childEntries(value), path });
    }
    if (typeof value !== "string") yield null;
  }
};

export const searchReportText = async (
  parsed: unknown,
  query: string,
  signal: AbortSignal
): Promise<ReportTextMatch[]> => {
  signal.throwIfAborted();
  const pattern = reportTextPattern(query);
  if (!pattern || !searchableObject(parsed)) return [];
  const matches: ReportTextMatch[] = [];
  let deadline = performance.now() + 8;
  for (const entry of parsedText(parsed)) {
    signal.throwIfAborted();
    if (entry && pattern.test(entry.value)) matches.push(entry);
    // Half a 60 Hz frame is a cooperative work budget, not a search/result cap.
    // https://web.dev/articles/optimize-long-tasks
    if (performance.now() < deadline) continue;
    await new Promise<void>(resolve => setTimeout(resolve, 0));
    deadline = performance.now() + 8;
  }
  signal.throwIfAborted();
  return matches;
};
