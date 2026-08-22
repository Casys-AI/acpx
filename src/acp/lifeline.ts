import { spawn, type ChildProcess, type ChildProcessByStdio } from "node:child_process";
import { createHash } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { Readable, Writable } from "node:stream";
import { fileURLToPath } from "node:url";
import { isChildProcessRunning, waitForChildExit, waitForSpawn } from "./client-process.js";

const ARMED_MESSAGE = "ARMED\n";
const ARMED_TIMEOUT_MS = 1_000;
const MAX_HANDSHAKE_OUTPUT = 128;
const UNARMED_STOP_GRACE_MS = 500;

export type LifelineWatchdog = ChildProcessByStdio<Writable, Readable, Readable>;

export function supportsProcessTreeLifeline(platform: NodeJS.Platform = process.platform): boolean {
  return platform === "darwin" || platform === "linux";
}

export function resolvePackagedLifelineHelper(
  platform: NodeJS.Platform = process.platform,
  arch: string = process.arch,
): string | undefined {
  if (!supportsProcessTreeLifeline(platform)) {
    return undefined;
  }

  const packageRoot = findPackageRoot();
  if (!packageRoot) {
    return undefined;
  }
  const nativeDir = path.join(packageRoot, "dist", "native");
  const candidate = path.join(nativeDir, "lifeline");
  return validatePackagedLifelineHelper(candidate, nativeDir, packageRoot, platform, arch)
    ? candidate
    : undefined;
}

export async function startLifelineWatchdog(
  helper: string,
  bridgePgid: number,
  handshakeTimeoutMs = ARMED_TIMEOUT_MS,
): Promise<LifelineWatchdog> {
  const watchdog = spawn(helper, [String(bridgePgid)], {
    cwd: path.dirname(helper),
    detached: true,
    env: {},
    stdio: ["pipe", "pipe", "pipe"],
    windowsHide: true,
  }) as LifelineWatchdog;

  try {
    await waitForSpawn(watchdog);
    await waitForArmed(watchdog, handshakeTimeoutMs);
    watchdog.stdout.destroy();
    watchdog.stderr.destroy();
    watchdog.unref();
    return watchdog;
  } catch (error) {
    await stopUnarmedWatchdog(watchdog);
    throw error;
  }
}

export function releaseLifelineWatchdog(watchdog: LifelineWatchdog | undefined): void {
  if (!watchdog?.stdin || watchdog.stdin.destroyed) {
    return;
  }
  try {
    watchdog.stdin.once("error", () => {});
    watchdog.stdin.end("R");
  } catch {
    // best effort after the bridge group is already proved empty
  }
}

export async function reapSpawnedProcessGroup(
  child: ChildProcess,
  termGraceMs: number,
  killGraceMs: number,
): Promise<boolean> {
  if (child.pid === undefined) {
    child.kill("SIGTERM");
    return !isChildProcessRunning(child);
  }

  signalProcessGroup(child.pid, "SIGTERM");
  let reaped = await waitForChildAndProcessGroupExit(child, child.pid, termGraceMs);
  if (!reaped) {
    signalProcessGroup(child.pid, "SIGKILL");
    reaped = await waitForChildAndProcessGroupExit(child, child.pid, killGraceMs);
  }
  child.stdin?.destroy();
  child.stdout?.destroy();
  child.stderr?.destroy();
  return reaped;
}

export async function waitForChildAndProcessGroupExit(
  child: ChildProcess,
  processGroupId: number,
  timeoutMs: number,
): Promise<boolean> {
  const deadline = Date.now() + Math.max(0, timeoutMs);
  while (true) {
    if (!isChildProcessRunning(child) && !hasLiveProcessGroup(processGroupId)) {
      return true;
    }
    const remainingMs = deadline - Date.now();
    if (remainingMs <= 0) {
      return false;
    }
    await delay(Math.min(20, remainingMs));
  }
}

export function hasLiveProcessGroup(processGroupId: number): boolean {
  try {
    process.kill(-processGroupId, 0);
    return true;
  } catch (error) {
    return errorCode(error) === "EPERM";
  }
}

function findPackageRoot(): string | undefined {
  let current = path.dirname(fileURLToPath(import.meta.url));
  while (true) {
    if (isAcpxPackageRoot(current)) {
      return current;
    }
    const parent = path.dirname(current);
    if (parent === current) {
      return undefined;
    }
    current = parent;
  }
}

function isAcpxPackageRoot(candidate: string): boolean {
  try {
    const parsed = JSON.parse(fs.readFileSync(path.join(candidate, "package.json"), "utf8")) as {
      name?: unknown;
    };
    return parsed.name === "acpx";
  } catch {
    return false;
  }
}

export function validatePackagedLifelineHelper(
  candidate: string,
  nativeDir: string,
  packageRoot: string,
  platform: NodeJS.Platform = process.platform,
  arch: string = process.arch,
): boolean {
  try {
    const packageStat = fs.statSync(path.join(packageRoot, "package.json"));
    if (!isTrustedPackageFile(candidate, nativeDir, packageStat.uid, true)) {
      return false;
    }
    const manifestPath = path.join(nativeDir, "lifeline.json");
    if (!isTrustedPackageFile(manifestPath, nativeDir, packageStat.uid, false)) {
      return false;
    }
    const expectedSha256 = readManifestSha256(manifestPath, platform, arch);
    if (!expectedSha256) {
      return false;
    }
    const actualSha256 = createHash("sha256").update(fs.readFileSync(candidate)).digest("hex");
    return actualSha256 === expectedSha256;
  } catch {
    return false;
  }
}

function readManifestSha256(
  manifestPath: string,
  platform: NodeJS.Platform,
  arch: string,
): string | undefined {
  const manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8")) as {
    platform?: unknown;
    arch?: unknown;
    sha256?: unknown;
  };
  if (manifest.platform !== platform || manifest.arch !== arch) {
    return undefined;
  }
  if (typeof manifest.sha256 !== "string" || !/^[a-f0-9]{64}$/.test(manifest.sha256)) {
    return undefined;
  }
  return manifest.sha256;
}

function isTrustedPackageFile(
  candidate: string,
  nativeDir: string,
  packageOwnerUid: number,
  executable: boolean,
): boolean {
  const linkStat = fs.lstatSync(candidate);
  if (
    !linkStat.isFile() ||
    linkStat.isSymbolicLink() ||
    linkStat.uid !== packageOwnerUid ||
    (linkStat.mode & 0o022) !== 0
  ) {
    return false;
  }
  const realNativeDir = fs.realpathSync(nativeDir);
  const realCandidate = fs.realpathSync(candidate);
  if (path.dirname(realCandidate) !== realNativeDir) {
    return false;
  }
  if (executable) {
    fs.accessSync(candidate, fs.constants.X_OK);
  }
  return true;
}

function signalProcessGroup(processGroupId: number, signal: NodeJS.Signals): void {
  try {
    process.kill(-processGroupId, signal);
  } catch {
    // best effort; the group may already be gone
  }
}

function errorCode(error: unknown): string | undefined {
  if (typeof error !== "object" || error === null || !("code" in error)) {
    return undefined;
  }
  return typeof error.code === "string" ? error.code : undefined;
}

async function delay(ms: number): Promise<void> {
  await new Promise<void>((resolve) => setTimeout(resolve, ms));
}

function waitForArmed(watchdog: LifelineWatchdog, timeoutMs: number): Promise<void> {
  return new Promise<void>((resolve, reject) => {
    let output = "";
    let settled = false;
    const timer = setTimeout(
      () => fail(new Error(`lifeline did not arm within ${timeoutMs}ms`)),
      Math.max(1, timeoutMs),
    );

    const cleanup = (): void => {
      clearTimeout(timer);
      watchdog.stdout.off("data", onData);
      watchdog.off("error", onError);
      watchdog.off("exit", onExit);
    };
    const fail = (error: Error): void => {
      if (settled) {
        return;
      }
      settled = true;
      cleanup();
      reject(error);
    };
    const onData = (chunk: Buffer | string): void => {
      output += typeof chunk === "string" ? chunk : chunk.toString("utf8");
      if (output.length > MAX_HANDSHAKE_OUTPUT) {
        fail(new Error("lifeline handshake exceeded its output limit"));
        return;
      }
      if (output === ARMED_MESSAGE) {
        settled = true;
        cleanup();
        resolve();
        return;
      }
      if (!ARMED_MESSAGE.startsWith(output)) {
        fail(new Error(`invalid lifeline handshake: ${JSON.stringify(output)}`));
      }
    };
    const onError = (error: Error): void => fail(error);
    const onExit = (code: number | null, signal: NodeJS.Signals | null): void => {
      fail(new Error(`lifeline exited before arming (code=${code}, signal=${signal})`));
    };

    if (watchdog.exitCode !== null || watchdog.signalCode !== null) {
      onExit(watchdog.exitCode, watchdog.signalCode);
      return;
    }
    watchdog.stdout.on("data", onData);
    watchdog.once("error", onError);
    watchdog.once("exit", onExit);
  });
}

async function stopUnarmedWatchdog(watchdog: LifelineWatchdog): Promise<void> {
  watchdog.stdin.destroy();
  const exited = await waitForChildExit(watchdog, UNARMED_STOP_GRACE_MS);
  if (!exited) {
    // The trusted helper may still be reaping the bridge group. Never kill it
    // before the owner independently proves that group empty.
    watchdog.unref();
  }
  watchdog.stdout.destroy();
  watchdog.stderr.destroy();
}
