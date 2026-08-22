import assert from "node:assert/strict";
import { spawn, type ChildProcess } from "node:child_process";
import { createHash } from "node:crypto";
import fs from "node:fs/promises";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { AcpClient } from "../src/acp/client.js";
import {
  reapSpawnedProcessGroup,
  resolvePackagedLifelineHelper,
  startLifelineWatchdog,
  supportsProcessTreeLifeline,
  validatePackagedLifelineHelper,
} from "../src/acp/lifeline.js";
import { isProcessAlive } from "../src/process-liveness.js";
import { fileExists, withTempDir } from "./runtime-test-helpers.js";

const MOCK_AGENT_PATH = fileURLToPath(new URL("./mock-agent.js", import.meta.url));

test("process-tree lifeline support is explicit by platform", () => {
  assert.equal(supportsProcessTreeLifeline("darwin"), true);
  assert.equal(supportsProcessTreeLifeline("linux"), true);
  assert.equal(supportsProcessTreeLifeline("win32"), false);
  assert.equal(supportsProcessTreeLifeline("freebsd"), false);
});

test("lifeline resolves only the real package-relative helper", async (t) => {
  if (!supportsProcessTreeLifeline()) {
    t.skip("packaged native lifeline is unavailable on this platform");
    return;
  }

  const expected = path.join(process.cwd(), "dist", "native", "lifeline");
  const originalCwd = process.cwd();
  const previousHome = process.env.HOME;
  const previousOverride = process.env.ACPX_LIFELINE_HELPER;

  await withTempDir("acpx-lifeline-resolution-", async (tempDir) => {
    const fakeHelper = path.join(tempDir, "fake-helper");
    await fs.writeFile(fakeHelper, "#!/bin/sh\nexit 99\n", { mode: 0o755 });
    process.env.HOME = tempDir;
    process.env.ACPX_LIFELINE_HELPER = fakeHelper;
    process.chdir(tempDir);
    try {
      assert.equal(resolvePackagedLifelineHelper(), expected);
      const stat = await fs.lstat(expected);
      assert.equal(stat.isFile(), true);
      assert.equal(stat.isSymbolicLink(), false);
      assert.equal(stat.nlink, 1);
      assert.equal(stat.mode & 0o022, 0);
    } finally {
      process.chdir(originalCwd);
      restoreEnvironment("HOME", previousHome);
      restoreEnvironment("ACPX_LIFELINE_HELPER", previousOverride);
    }
  });
});

test("packaged helper validation accepts verified hardlinks and rejects substitutions", async () => {
  await withTempDir("acpx-lifeline-validation-", async (packageRoot) => {
    const nativeDir = path.join(packageRoot, "dist", "native");
    const packageJson = path.join(packageRoot, "package.json");
    const target = path.join(nativeDir, "target");
    const candidate = path.join(nativeDir, "lifeline-test");
    const manifest = path.join(nativeDir, "lifeline.json");
    await fs.mkdir(nativeDir, { recursive: true });
    await fs.writeFile(packageJson, '{"name":"acpx"}\n', "utf8");
    await fs.writeFile(candidate, "native helper", { mode: 0o755 });
    await writeHelperManifest(manifest, "native helper");
    assert.equal(validatePackagedLifelineHelper(candidate, nativeDir, packageRoot), true);

    await fs.chmod(candidate, 0o775);
    assert.equal(validatePackagedLifelineHelper(candidate, nativeDir, packageRoot), false);
    await fs.rm(candidate);

    await fs.writeFile(target, "native helper", { mode: 0o755 });
    await fs.symlink(target, candidate);
    assert.equal(validatePackagedLifelineHelper(candidate, nativeDir, packageRoot), false);
    await fs.rm(candidate);

    await fs.link(target, candidate);
    assert.equal(validatePackagedLifelineHelper(candidate, nativeDir, packageRoot), true);
    await fs.rm(candidate);

    const manifestContents = await fs.readFile(manifest, "utf8");
    const manifestTarget = path.join(nativeDir, "manifest-target.json");
    await fs.rename(manifest, manifestTarget);
    await fs.link(manifestTarget, manifest);
    assert.equal(validatePackagedLifelineHelper(target, nativeDir, packageRoot), true);
    await fs.rm(manifest);
    await fs.symlink(manifestTarget, manifest);
    assert.equal(validatePackagedLifelineHelper(target, nativeDir, packageRoot), false);
    await fs.rm(manifest);
    await fs.writeFile(manifest, manifestContents, "utf8");

    await fs.writeFile(candidate, "tampered helper", { mode: 0o755 });
    assert.equal(validatePackagedLifelineHelper(candidate, nativeDir, packageRoot), false);
  });
});

test("packaged helper validation rejects a mismatched host manifest", async () => {
  await withTempDir("acpx-lifeline-host-validation-", async (packageRoot) => {
    const nativeDir = path.join(packageRoot, "dist", "native");
    const candidate = path.join(nativeDir, "lifeline");
    const manifest = path.join(nativeDir, "lifeline.json");
    await fs.mkdir(nativeDir, { recursive: true });
    await fs.writeFile(path.join(packageRoot, "package.json"), '{"name":"acpx"}\n', "utf8");
    await fs.writeFile(candidate, "native helper", { mode: 0o755 });
    await writeHelperManifest(manifest, "native helper", "freebsd");

    assert.equal(validatePackagedLifelineHelper(candidate, nativeDir, packageRoot), false);
  });
});

test("native lifeline reaps bridge group on owner-pipe EOF", async (t) => {
  if (!supportsProcessTreeLifeline()) {
    t.skip("native lifeline is unavailable on this platform");
    return;
  }
  const helper = resolvePackagedLifelineHelper();
  assert(helper, "packaged helper must exist before POSIX tests run");

  await withTempDir("acpx-lifeline-native-eof-", async (tempDir) => {
    const tree = await spawnProcessTree(tempDir);
    let watchdog: ChildProcess | undefined;
    try {
      watchdog = await startLifelineWatchdog(helper, tree.bridgePid);
      assert.equal(isProcessAlive(watchdog.pid), true);
      watchdog.stdin?.destroy();
      await waitUntil(() =>
        Promise.resolve(!isProcessAlive(tree.bridgePid) && !isProcessAlive(tree.grandchildPid)),
      );
      await waitForExit(watchdog);
      assert.equal(isProcessAlive(tree.bridgePid), false);
      assert.equal(isProcessAlive(tree.grandchildPid), false);
    } finally {
      watchdog?.stdin?.destroy();
      killProcessGroup(tree.bridgePid);
      killProcess(tree.grandchildPid);
    }
  });
});

test("native lifeline reaps when the owner disappears during ARMED acknowledgement", async (t) => {
  if (!supportsProcessTreeLifeline()) {
    t.skip("native lifeline is unavailable on this platform");
    return;
  }
  const helper = resolvePackagedLifelineHelper();
  assert(helper, "packaged helper must exist before POSIX tests run");

  await withTempDir("acpx-lifeline-ack-owner-death-", async (tempDir) => {
    const tree = await spawnProcessTree(tempDir);
    const watchdog = spawn(helper, [String(tree.bridgePid)], {
      detached: true,
      env: {},
      stdio: ["pipe", "pipe", "ignore"],
    });
    try {
      watchdog.stdout?.destroy();
      watchdog.stdin?.destroy();
      await waitUntil(() =>
        Promise.resolve(!isProcessAlive(tree.bridgePid) && !isProcessAlive(tree.grandchildPid)),
      );
      await waitForExit(watchdog);
      assert.equal(isProcessAlive(tree.bridgePid), false);
      assert.equal(isProcessAlive(tree.grandchildPid), false);
    } finally {
      watchdog.stdin?.destroy();
      killProcess(watchdog.pid);
      killProcessGroup(tree.bridgePid);
      killProcess(tree.grandchildPid);
    }
  });
});

test("native lifeline reaps descendants when the bridge leader crashes", async (t) => {
  if (!supportsProcessTreeLifeline()) {
    t.skip("native lifeline is unavailable on this platform");
    return;
  }
  const helper = resolvePackagedLifelineHelper();
  assert(helper, "packaged helper must exist before POSIX tests run");

  await withTempDir("acpx-lifeline-bridge-crash-", async (tempDir) => {
    const tree = await spawnProcessTree(tempDir);
    let watchdog: ChildProcess | undefined;
    try {
      watchdog = await startLifelineWatchdog(helper, tree.bridgePid);
      process.kill(tree.bridgePid, "SIGKILL");
      await waitUntil(() =>
        Promise.resolve(!isProcessAlive(tree.bridgePid) && !isProcessAlive(tree.grandchildPid)),
      );
      await waitForExit(watchdog);
      assert.equal(isProcessAlive(tree.grandchildPid), false);
    } finally {
      watchdog?.stdin?.destroy();
      killProcess(watchdog?.pid);
      killProcessGroup(tree.bridgePid);
      killProcess(tree.grandchildPid);
    }
  });
});

test("failed lifeline handshake is followed by independent group cleanup", async (t) => {
  if (!supportsProcessTreeLifeline()) {
    t.skip("native lifeline is unavailable on this platform");
    return;
  }

  await withTempDir("acpx-lifeline-arm-failure-", async (tempDir) => {
    const fakeHelper = path.join(tempDir, "fake-helper");
    await fs.writeFile(fakeHelper, "#!/bin/sh\nprintf 'NOT_ARMED\\n'\nexit 2\n", {
      mode: 0o755,
    });
    const tree = await spawnProcessTree(tempDir);
    try {
      await assert.rejects(
        () => startLifelineWatchdog(fakeHelper, tree.bridgePid),
        /invalid lifeline handshake|exited before arming/,
      );
      assert.equal(
        await reapSpawnedProcessGroup(tree.bridge, 500, 500),
        true,
        "owner must independently prove the group was reaped",
      );
      assert.equal(isProcessAlive(tree.bridgePid), false);
      assert.equal(isProcessAlive(tree.grandchildPid), false);
    } finally {
      killProcessGroup(tree.bridgePid);
      killProcess(tree.grandchildPid);
    }
  });
});

test("AcpClient graceful close reaps bridge descendants and watchdog", async (t) => {
  if (!supportsProcessTreeLifeline()) {
    t.skip("native lifeline is unavailable on this platform");
    return;
  }

  await withTempDir("acpx-lifeline-close-", async (tempDir) => {
    const bridgePidFile = path.join(tempDir, "bridge.pid");
    const grandchildPidFile = path.join(tempDir, "grandchild.pid");
    const client = makeTreeClient(tempDir, bridgePidFile, grandchildPidFile, []);
    let bridgePid: number | undefined;
    let grandchildPid: number | undefined;
    let watchdogPid: number | undefined;

    try {
      await client.start();
      await waitUntil(() => fileExists(bridgePidFile));
      await waitUntil(() => fileExists(grandchildPidFile));
      bridgePid = await readPidFile(bridgePidFile);
      grandchildPid = await readPidFile(grandchildPidFile);
      watchdogPid = lifelinePid(client);
      assert.equal(client.getAgentPid(), bridgePid);
      assert(watchdogPid && watchdogPid !== bridgePid);

      await client.close();
      await waitUntil(() =>
        Promise.resolve(
          !isProcessAlive(bridgePid) &&
            !isProcessAlive(grandchildPid) &&
            !isProcessAlive(watchdogPid),
        ),
      );
    } finally {
      await client.close().catch(() => {});
      killProcessGroup(bridgePid);
      killProcess(grandchildPid);
      killProcess(watchdogPid);
    }
  });
});

test("AcpClient initialization failure reaps bridge descendants", async (t) => {
  if (!supportsProcessTreeLifeline()) {
    t.skip("native lifeline is unavailable on this platform");
    return;
  }

  await withTempDir("acpx-lifeline-init-failure-", async (tempDir) => {
    const bridgePidFile = path.join(tempDir, "bridge.pid");
    const grandchildPidFile = path.join(tempDir, "grandchild.pid");
    const client = makeTreeClient(tempDir, bridgePidFile, grandchildPidFile, [
      "--fail-initialize",
      "--ignore-sigterm",
    ]);
    let bridgePid: number | undefined;
    let grandchildPid: number | undefined;

    try {
      await assert.rejects(() => client.start(), /initialize failed/i);
      await waitUntil(() => fileExists(bridgePidFile));
      await waitUntil(() => fileExists(grandchildPidFile));
      bridgePid = await readPidFile(bridgePidFile);
      grandchildPid = await readPidFile(grandchildPidFile);
      await waitUntil(() =>
        Promise.resolve(!isProcessAlive(bridgePid) && !isProcessAlive(grandchildPid)),
      );
    } finally {
      await client.close().catch(() => {});
      killProcessGroup(bridgePid);
      killProcess(grandchildPid);
    }
  });
});

test("repeated ACP sessions leave no bridge, descendant, or lifeline buildup", async (t) => {
  if (!supportsProcessTreeLifeline()) {
    t.skip("native lifeline is unavailable on this platform");
    return;
  }

  await withTempDir("acpx-lifeline-repeated-sessions-", async (tempDir) => {
    const observedPids: number[] = [];

    for (let iteration = 0; iteration < 5; iteration += 1) {
      const bridgePidFile = path.join(tempDir, `bridge-${iteration}.pid`);
      const grandchildPidFile = path.join(tempDir, `grandchild-${iteration}.pid`);
      const client = makeTreeClient(tempDir, bridgePidFile, grandchildPidFile, []);
      let watchdogPid: number | undefined;

      try {
        await client.start();
        await client.createSession();
        await waitUntil(() => fileExists(bridgePidFile));
        await waitUntil(() => fileExists(grandchildPidFile));
        const bridgePid = await readPidFile(bridgePidFile);
        const grandchildPid = await readPidFile(grandchildPidFile);
        watchdogPid = lifelinePid(client);
        assert.equal(client.getAgentPid(), bridgePid, "lifecycle PID must remain the bridge");
        assert(watchdogPid, "lifeline must be armed for every session");
        observedPids.push(bridgePid, grandchildPid, watchdogPid);

        await client.close();
        await waitUntil(() => Promise.resolve(observedPids.every((pid) => !isProcessAlive(pid))));
      } finally {
        await client.close().catch(() => {});
        killProcess(watchdogPid);
      }
    }

    assert.equal(
      observedPids.some((pid) => isProcessAlive(pid)),
      false,
    );
  });
});

type SpawnedTree = {
  bridge: ChildProcess;
  bridgePid: number;
  grandchildPid: number;
};

async function spawnProcessTree(tempDir: string): Promise<SpawnedTree> {
  const bridgePidFile = path.join(tempDir, `native-bridge-${process.pid}.pid`);
  const grandchildPidFile = path.join(tempDir, `native-grandchild-${process.pid}.pid`);
  const grandchildScript = "process.on('SIGTERM', () => {}); setInterval(() => {}, 1000)";
  const bridgeScript = `
const { spawn } = require("node:child_process");
const fs = require("node:fs");
const grandchild = spawn(process.execPath, ["--eval", ${JSON.stringify(grandchildScript)}], { stdio: "ignore" });
grandchild.unref();
fs.writeFileSync(${JSON.stringify(grandchildPidFile)}, String(grandchild.pid));
fs.writeFileSync(${JSON.stringify(bridgePidFile)}, String(process.pid));
process.on("SIGTERM", () => {});
setInterval(() => {}, 1000);
`;
  const bridge = spawn(process.execPath, ["--eval", bridgeScript], {
    detached: true,
    stdio: "ignore",
  });
  assert(bridge.pid);
  bridge.unref();
  await waitUntil(() => fileExists(bridgePidFile));
  await waitUntil(() => fileExists(grandchildPidFile));
  return {
    bridge,
    bridgePid: await readPidFile(bridgePidFile),
    grandchildPid: await readPidFile(grandchildPidFile),
  };
}

function makeTreeClient(
  cwd: string,
  bridgePidFile: string,
  grandchildPidFile: string,
  extraArgs: string[],
): AcpClient {
  return new AcpClient({
    agentCommand: [
      "node",
      JSON.stringify(MOCK_AGENT_PATH),
      "--pid-file",
      JSON.stringify(bridgePidFile),
      "--grandchild-pid-file",
      JSON.stringify(grandchildPidFile),
      "--grandchild-ignore-sigterm",
      "--stay-alive-after-stdin-end",
      ...extraArgs,
    ].join(" "),
    cwd,
    permissionMode: "approve-reads",
  });
}

function lifelinePid(client: AcpClient): number | undefined {
  return (
    client as unknown as {
      lifelineWatchdog?: ChildProcess;
    }
  ).lifelineWatchdog?.pid;
}

async function readPidFile(filePath: string): Promise<number> {
  const pid = Number((await fs.readFile(filePath, "utf8")).trim());
  assert(Number.isInteger(pid) && pid > 1);
  return pid;
}

async function waitForExit(child: ChildProcess, timeoutMs = 3_000): Promise<void> {
  if (child.exitCode !== null || child.signalCode !== null) {
    return;
  }
  await Promise.race([
    new Promise<void>((resolve) => child.once("exit", () => resolve())),
    new Promise<never>((_, reject) =>
      setTimeout(() => reject(new Error("child did not exit in time")), timeoutMs),
    ),
  ]);
}

async function waitUntil(
  condition: () => Promise<boolean>,
  timeoutMs = 3_000,
  pollMs = 25,
): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (await condition()) {
      return;
    }
    await new Promise<void>((resolve) => setTimeout(resolve, pollMs));
  }
  throw new Error(`condition not met within ${timeoutMs}ms`);
}

function killProcessGroup(pgid: number | undefined): void {
  if (!pgid) {
    return;
  }
  try {
    process.kill(-pgid, "SIGKILL");
  } catch {
    // best effort test cleanup
  }
}

function killProcess(pid: number | undefined): void {
  if (!pid || !isProcessAlive(pid)) {
    return;
  }
  try {
    process.kill(pid, "SIGKILL");
  } catch {
    // best effort test cleanup
  }
}

function restoreEnvironment(key: string, value: string | undefined): void {
  if (value === undefined) {
    delete process.env[key];
  } else {
    process.env[key] = value;
  }
}

async function writeHelperManifest(
  manifestPath: string,
  helperContents: string,
  platform: NodeJS.Platform = process.platform,
): Promise<void> {
  const sha256 = createHash("sha256").update(helperContents).digest("hex");
  await fs.writeFile(
    manifestPath,
    `${JSON.stringify({ platform, arch: process.arch, sha256 })}\n`,
    "utf8",
  );
}
