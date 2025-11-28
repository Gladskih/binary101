"use strict";

import { mkdir, stat, writeFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

interface FixtureSourceConfig {
  label: string;
  apiRoot: string;
}

interface FixtureSource extends FixtureSourceConfig {
  basePath: string;
  owner: string;
  repo: string;
  ref: string | null;
}

interface ManifestEntry {
  source: string;
  relativePath: string;
  size: number;
  sha: string | null;
}

interface ManifestFile {
  generatedAt: string;
  entries: ManifestEntry[];
}

interface GitTreeItem {
  path: string;
  type: string;
  size?: number;
  sha?: string;
}

interface GitTreeResponse {
  tree: GitTreeItem[];
  truncated?: boolean;
}

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const projectRoot = resolve(__dirname, "..");
const fixturesRoot = join(projectRoot, "external-pe-fixtures");
const manifestPath = join(fixturesRoot, "manifest.json");

const allowedExtensions = [".exe", ".dll", ".sys", ".ocx", ".scr"];

const sourceConfigs: FixtureSourceConfig[] = [
  {
    label: "corkami-pocs-PE",
    apiRoot: "https://api.github.com/repos/corkami/pocs/contents/PE"
  },
  {
    label: "radare2-testbins-pe",
    apiRoot: "https://api.github.com/repos/radareorg/radare2-testbins/contents/pe"
  },
  {
    label: "hasherezade-pesieve-tests",
    apiRoot: "https://api.github.com/repos/hasherezade/pesieve_tests/contents"
  }
];

const sources: FixtureSource[] = sourceConfigs.map(source => {
  const parsed = parseApiRoot(source.apiRoot);
  return { ...source, ...parsed };
});

function parseApiRoot(apiRoot: string): { owner: string; repo: string; basePath: string; ref: string | null } {
  const url = new URL(apiRoot);
  const segments = url.pathname.split("/").filter(Boolean);
  const reposIndex = segments.indexOf("repos");
  if (reposIndex === -1 || segments.length < reposIndex + 4 || segments[reposIndex + 3] !== "contents") {
    throw new Error(`Unsupported apiRoot format: ${apiRoot}`);
  }
  const owner = segments[reposIndex + 1];
  const repo = segments[reposIndex + 2];
  if (!owner || !repo) throw new Error(`Unable to parse owner/repo from apiRoot: ${apiRoot}`);
  const afterContents = segments.slice(reposIndex + 4);
  const basePath = afterContents.join("/");
  const ref = url.searchParams.get("ref");
  return { owner, repo, basePath: basePath.replace(/^\/+/, ""), ref };
}

function buildHeaders(): Record<string, string> {
  const headers: Record<string, string> = {
    "User-Agent": "binary101-fixture-fetcher",
    Accept: "application/vnd.github.v3+json"
  };
  const token = process.env["GITHUB_TOKEN"];
  if (token) headers["Authorization"] = `Bearer ${token}`;
  return headers;
}

function hasAllowedExtension(name: string): boolean {
  const lower = name.toLowerCase();
  return allowedExtensions.some(ext => lower.endsWith(ext));
}

function toSafeRelativePath(path: string): string {
  const normalized = path.replace(/\\/g, "/").replace(/^\/+/, "");
  if (normalized.split("/").some(part => part === ".." || part === "")) {
    throw new Error(`Unsafe relative path from GitHub contents: ${path}`);
  }
  return normalized;
}

function toRelativePath(fullPath: string, basePath: string): string | null {
  const normalizedFull = fullPath.replace(/^\/+/, "");
  const normalizedBase = basePath ? basePath.replace(/^\/+/, "") : "";
  if (!normalizedBase) return toSafeRelativePath(normalizedFull);
  const prefix = `${normalizedBase}/`;
  if (normalizedFull === normalizedBase) return null;
  if (normalizedFull.startsWith(prefix)) return toSafeRelativePath(normalizedFull.slice(prefix.length));
  return null;
}

async function fetchJson<T>(url: string, headers: Record<string, string>): Promise<T> {
  const response = await fetch(url, { headers });
  if (!response.ok) {
    const body = await response.text().catch(() => "");
    const hint = response.status === 403 ? " (possible rate limit, set GITHUB_TOKEN)" : "";
    throw new Error(`GitHub request failed ${response.status}${hint}: ${url}${body ? ` - ${body}` : ""}`);
  }
  return response.json() as Promise<T>;
}

async function resolveRef(source: FixtureSource, headers: Record<string, string>): Promise<string> {
  if (source.ref) return source.ref;
  const repoInfo = await fetchJson<{ default_branch?: string }>(
    `https://api.github.com/repos/${source.owner}/${source.repo}`,
    headers
  );
  return repoInfo.default_branch ?? "master";
}

async function fetchTree(
  source: FixtureSource,
  ref: string,
  headers: Record<string, string>
): Promise<GitTreeItem[]> {
  const treeUrl = `https://api.github.com/repos/${source.owner}/${source.repo}/git/trees/${encodeURIComponent(ref)}?recursive=1`;
  const tree = await fetchJson<GitTreeResponse>(treeUrl, headers);
  if (tree.truncated) {
    console.warn(`Tree listing truncated for ${source.label} (${source.owner}/${source.repo} at ${ref})`);
  }
  return tree.tree ?? [];
}

async function fileHasExpectedSize(path: string, expectedSize: number | undefined): Promise<boolean> {
  if (expectedSize == null || !existsSync(path)) return false;
  const fileStats = await stat(path);
  return fileStats.size === expectedSize;
}

async function downloadBinary(
  url: string,
  targetPath: string,
  expectedSize: number | undefined,
  headers: Record<string, string>
): Promise<number> {
  if (!url) throw new Error(`Missing download URL for ${targetPath}`);
  if (await fileHasExpectedSize(targetPath, expectedSize)) {
    return expectedSize ?? (await stat(targetPath)).size;
  }
  const response = await fetch(url, { headers });
  if (!response.ok) {
    const body = await response.text().catch(() => "");
    const hint = response.status === 403 ? " (possible rate limit, set GITHUB_TOKEN)" : "";
    throw new Error(`Download failed ${response.status}${hint}: ${url}${body ? ` - ${body}` : ""}`);
  }
  const buffer = await response.arrayBuffer();
  const bytes = new Uint8Array(buffer);
  await mkdir(dirname(targetPath), { recursive: true });
  await writeFile(targetPath, bytes);
  if (expectedSize && expectedSize !== bytes.length) {
    console.warn(
      `Size mismatch for ${targetPath}: expected ${expectedSize}, downloaded ${bytes.length}. Kept downloaded bytes.`
    );
  }
  return bytes.length;
}

function buildDownloadUrl(source: FixtureSource, ref: string, fullPath: string): string {
  const normalized = fullPath.replace(/^\/+/, "");
  return `https://raw.githubusercontent.com/${source.owner}/${source.repo}/${ref}/${normalized}`;
}

function buildTargetPath(relativePath: string, sourceLabel: string): string {
  const parts = relativePath.split("/").filter(Boolean);
  const target = resolve(fixturesRoot, sourceLabel, ...parts);
  if (!target.startsWith(fixturesRoot)) {
    throw new Error(`Refusing to write outside fixture root: ${target}`);
  }
  return target;
}

async function collectSource(
  source: FixtureSource,
  headers: Record<string, string>,
  entries: ManifestEntry[]
): Promise<void> {
  const ref = await resolveRef(source, headers);
  const treeItems = await fetchTree(source, ref, headers);
  for (const item of treeItems) {
    if (item.type !== "blob") continue;
    const relativePath = toRelativePath(item.path, source.basePath);
    if (!relativePath) continue;
    const name = relativePath.split("/").pop();
    if (!name || !hasAllowedExtension(name)) continue;
    const targetPath = buildTargetPath(relativePath, source.label);
    const downloadUrl = buildDownloadUrl(source, ref, item.path);
    const writtenSize = await downloadBinary(
      downloadUrl,
      targetPath,
      typeof item.size === "number" ? item.size : undefined,
      headers
    );
    entries.push({
      source: source.label,
      relativePath,
      size: writtenSize,
      sha: item.sha ?? null
    });
  }
}

async function writeManifest(entries: ManifestEntry[]): Promise<void> {
  const manifest: ManifestFile = {
    generatedAt: new Date().toISOString(),
    entries: entries.sort((a, b) => {
      if (a.source === b.source) return a.relativePath.localeCompare(b.relativePath);
      return a.source.localeCompare(b.source);
    })
  };
  await mkdir(fixturesRoot, { recursive: true });
  await writeFile(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);
}

async function main(): Promise<void> {
  const headers = buildHeaders();
  const entries: ManifestEntry[] = [];
  for (const source of sources) {
    console.log(`Collecting from ${source.label} (${source.apiRoot})`);
    await collectSource(source, headers, entries);
  }
  if (!entries.length) {
    throw new Error("No fixtures were downloaded. Check network access and source configuration.");
  }
  await writeManifest(entries);
  console.log(`Stored ${entries.length} fixtures in ${fixturesRoot}`);
  console.log(`Manifest written to ${manifestPath}`);
}

void main().catch(error => {
  console.error(error);
  process.exitCode = 1;
});
