import { cpSync, mkdirSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const projectRoot = resolve(__dirname, "..");
const distDir = join(projectRoot, "dist");

mkdirSync(distDir, { recursive: true });

const staticFiles = ["index.html", "style.css"];

for (const file of staticFiles) {
  const sourcePath = join(projectRoot, file);
  const targetPath = join(distDir, file);
  cpSync(sourcePath, targetPath);
}

