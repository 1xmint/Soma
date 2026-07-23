import { open, readFile, rename, unlink } from "node:fs/promises";
import path from "node:path";
import { randomBytes } from "node:crypto";
import { canonicalize, parseCanonicalJson } from "./canonicalize.mjs";
import { SomaError } from "./errors.mjs";

function processIsAlive(pid) {
  try { process.kill(pid, 0); return true; }
  catch (error) { return error.code !== "ESRCH"; }
}

async function releaseOwnedLock(file, handle, token) {
  await handle.close();
  const deadline = Date.now() + 5000;
  while (true) {
    try {
      const current = parseCanonicalJson(await readFile(file, "utf8"), "host succession lock");
      if (current.token !== token || current.pid !== process.pid) return;
      await unlink(file);
      return;
    } catch (error) {
      if (error.code === "ENOENT") return;
      if (!["EACCES", "EBUSY", "EPERM"].includes(error.code) || Date.now() >= deadline) throw error;
      await new Promise((resolve) => setTimeout(resolve, 25));
    }
  }
}

export async function acquireHostSuccessionLock(home, timeoutMs = 5000) {
  const file = path.join(home, "run", "host-succession.lock");
  const deadline = Date.now() + timeoutMs;
  const token = randomBytes(16).toString("hex");
  const owner = { schema_version: "soma.host-succession-lock.provisional-v1", pid: process.pid, token, created_at: new Date().toISOString() };
  let delayMs = 20;
  const jitterMs = Number.parseInt(token.slice(0, 2), 16) % 31;
  while (true) {
    try {
      const handle = await open(file, "wx", 0o600);
      await handle.writeFile(`${canonicalize(owner)}\n`, "utf8");
      await handle.sync();
      return () => releaseOwnedLock(file, handle, token);
    } catch (error) {
      if (!["EACCES", "EBUSY", "EEXIST", "EPERM"].includes(error.code)) throw error;
      let existing = null;
      try { existing = parseCanonicalJson(await readFile(file, "utf8"), "host succession lock"); } catch {}
      if (existing && Number.isSafeInteger(existing.pid) && existing.pid > 0 && /^[a-f0-9]{32}$/.test(existing.token || "") && !processIsAlive(existing.pid)) {
        const stale = `${file}.stale-${token}`;
        try { await rename(file, stale); await unlink(stale); continue; }
        catch (staleError) {
          if (staleError.code === "ENOENT") continue;
          if (!["EACCES", "EBUSY", "EPERM"].includes(staleError.code)) throw staleError;
        }
      }
      if (Date.now() >= deadline) throw new SomaError("host succession lock is held or cannot be safely identified", 7, "HOST_SUCCESSION_LOCKED");
      await new Promise((resolve) => setTimeout(resolve, delayMs + jitterMs));
      delayMs = Math.min(delayMs + 10, 200);
    }
  }
}
