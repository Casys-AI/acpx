import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { chmodSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

if (process.platform !== "darwin" && process.platform !== "linux") {
  process.exit(0);
}

const source = path.join(repoRoot, "native", "lifeline.c");
const outputDir = path.join(repoRoot, "dist", "native");
const output = path.join(outputDir, "lifeline");
const manifest = path.join(outputDir, "lifeline.json");
mkdirSync(outputDir, { recursive: true });

const compiler = process.env.CC ?? "cc";
const result = spawnSync(
  compiler,
  ["-std=c11", "-O2", "-Wall", "-Wextra", "-Werror", source, "-o", output],
  { stdio: "inherit" },
);

if (result.error) {
  throw result.error;
}
if (result.status !== 0) {
  process.exit(result.status ?? 1);
}

chmodSync(output, 0o755);
const sha256 = createHash("sha256").update(readFileSync(output)).digest("hex");
writeFileSync(
  manifest,
  `${JSON.stringify({ platform: process.platform, arch: process.arch, sha256 })}\n`,
  { mode: 0o644 },
);
