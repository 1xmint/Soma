import { spawnSync } from "node:child_process";
import { SomaError } from "./errors.mjs";

const ENTROPY_LABEL = "Somavera/Soma/DPAPI/v1";

function runPowerShell(script, input) {
  const result = spawnSync("powershell.exe", ["-NoProfile", "-NonInteractive", "-Command", script], {
    input,
    encoding: "utf8",
    windowsHide: true,
    maxBuffer: 1024 * 1024,
    timeout: 15000
  });
  if (result.error || result.status !== 0) {
    const message = result.error?.message || result.stderr.trim() || `PowerShell exited ${result.status}`;
    throw new SomaError("Windows secure storage operation failed", 8, "WINDOWS_DPAPI_FAILED", { cause: message });
  }
  return result.stdout.trim();
}

function dpapi(operation, bytes) {
  const method = operation === "protect" ? "Protect" : "Unprotect";
  const script = [
    "$ErrorActionPreference='Stop'",
    "Add-Type -AssemblyName System.Security",
    "$value=[Console]::In.ReadToEnd().Trim()",
    "$bytes=[Convert]::FromBase64String($value)",
    `$entropy=[Text.Encoding]::UTF8.GetBytes('${ENTROPY_LABEL}')`,
    `$result=[Security.Cryptography.ProtectedData]::${method}($bytes,$entropy,[Security.Cryptography.DataProtectionScope]::CurrentUser)`,
    "[Console]::Out.Write([Convert]::ToBase64String($result))"
  ].join(";");
  return Buffer.from(runPowerShell(script, Buffer.from(bytes).toString("base64")), "base64");
}

export function protectSecretBundle(secretBundle, allowInsecureDevelopment = false) {
  const plaintext = Buffer.from(JSON.stringify(secretBundle), "utf8");
  try {
    if (process.platform === "win32") {
      return {
        backend: "windows-dpapi-current-user-v1",
        security_degradation: null,
        blob: dpapi("protect", plaintext)
      };
    }
    if (!allowInsecureDevelopment) {
      throw new SomaError("no supported production secure store is available", 8, "SECURE_STORE_UNAVAILABLE");
    }
    return {
      backend: "development-plaintext-file-v1",
      security_degradation: "INSECURE_DEVELOPMENT_KEYSTORE",
      blob: Buffer.from(plaintext)
    };
  } finally {
    plaintext.fill(0);
  }
}

export function unprotectSecretBundle(backend, blob) {
  let plaintext;
  if (backend === "windows-dpapi-current-user-v1") plaintext = dpapi("unprotect", blob);
  else if (backend === "development-plaintext-file-v1") plaintext = Buffer.from(blob);
  else throw new SomaError("unknown keystore backend", 8, "KEYSTORE_BACKEND_UNKNOWN");
  try {
    return JSON.parse(plaintext.toString("utf8"));
  } finally {
    plaintext.fill(0);
  }
}

export function secureStoreSupport() {
  return {
    supported: process.platform === "win32",
    backend: process.platform === "win32" ? "windows-dpapi-current-user-v1" : null
  };
}
