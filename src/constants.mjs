import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

export const VERSION = "0.1.0";
export const RELEASE_ROOT = path.resolve(fileURLToPath(new URL("../", import.meta.url)));
export const EMPTY_HASH = "0".repeat(64);

export function defaultSomaHome() {
  if (process.platform === "win32") {
    const local = process.env.LOCALAPPDATA;
    if (!local) throw new Error("LOCALAPPDATA is unavailable");
    return path.join(local, "Somavera", "Soma");
  }
  if (process.platform === "darwin") {
    return path.join(os.homedir(), "Library", "Application Support", "Somavera", "Soma");
  }
  return path.join(process.env.XDG_STATE_HOME || path.join(os.homedir(), ".local", "state"), "somavera", "soma");
}

export const STATE_DIRECTORIES = Object.freeze([
  "config",
  "identity",
  "hosts",
  "hosts/candidates",
  "hosts/history",
  "hosts/transactions",
  "consent/grants",
  "consent/withdrawals",
  "consent/previews",
  "consent/denials",
  "evidence/anchors",
  "intelligence/queries",
  "intelligence/sources",
  "exports",
  "queue",
  "logs",
  "run"
]);
