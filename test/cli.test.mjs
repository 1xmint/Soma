import assert from "node:assert/strict";
import { mkdtemp, readFile, readdir, rm, stat, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.resolve(fileURLToPath(new URL("../", import.meta.url)));
const cli = path.join(root, "bin", "soma.mjs");
const preload = pathToFileURL(path.join(root, "test", "no-network-preload.mjs")).href;

function execute(args, trace, extraEnvironment = {}) {
  return spawnSync(process.execPath, [cli, ...args], {
    cwd: root,
    encoding: "utf8",
    windowsHide: true,
    timeout: 30000,
    env: {
      ...process.env,
      ...extraEnvironment,
      NODE_OPTIONS: `${process.env.NODE_OPTIONS || ""} --import=${preload}`.trim(),
      SOMA_NETWORK_TRACE: trace
    }
  });
}

async function traceAbsent(trace) {
  try {
    const metadata = await stat(trace);
    assert.equal(metadata.size, 0, "network trace was not empty");
  } catch (error) {
    if (error.code !== "ENOENT") throw error;
  }
}

async function files(directory) {
  const result = [];
  async function walk(current) {
    for (const entry of await readdir(current, { withFileTypes: true })) {
      const absolute = path.join(current, entry.name);
      if (entry.isDirectory()) await walk(absolute);
      else if (entry.isFile()) result.push(absolute);
    }
  }
  await walk(directory);
  return result;
}

async function temporaryHome(context) {
  const temporary = await mkdtemp(path.join(os.tmpdir(), "somavera-soma-test-"));
  context.after(() => rm(temporary, { recursive: true, force: true }));
  return {
    temporary,
    home: path.join(temporary, "home"),
    trace: path.join(temporary, "network.trace")
  };
}

test("init, doctor, status, and idempotent init are offline and observer-off", async (context) => {
  const { home, trace } = await temporaryHome(context);
  const common = ["--home", home, "--json"];

  const initialized = execute(["init", ...common, "--recovery", "none", "--label", "test-agent"], trace);
  assert.equal(initialized.status, 0, initialized.stderr || initialized.stdout);
  const initPayload = JSON.parse(initialized.stdout);
  assert.equal(initPayload.created, true);
  assert.equal(initPayload.observer.status, "off");
  assert.equal(initPayload.remote_mutation, false);
  assert.match(initPayload.keystore_backend, process.platform === "win32" ? /^windows-dpapi/ : /^development-plaintext/);
  await traceAbsent(trace);

  const doctor = execute(["doctor", ...common], trace);
  assert.equal(doctor.status, 0, doctor.stderr || doctor.stdout);
  const doctorPayload = JSON.parse(doctor.stdout);
  assert.equal(doctorPayload.offline, true);
  assert.equal(doctorPayload.network_checks_performed, 0);
  assert.deepEqual(doctorPayload.network_destinations, []);
  assert.equal(doctorPayload.observer.status, "off");
  assert.equal(doctorPayload.active_grants, 0);
  assert.equal(doctorPayload.permissions.owner_matches, true);
  assert.equal(doctorPayload.permissions.unauthorized_allow_count, 0);
  assert.equal(doctorPayload.permissions.unsafe_path_count, 0);
  assert.ok(doctorPayload.permissions.checked_path_count > 10);
  assert.equal(doctorPayload.release.authenticity, "self_manifest_integrity_only_untrusted");
  await traceAbsent(trace);

  const explicitNetworkDoctor = execute(["doctor", ...common, "--network"], trace);
  assert.equal(explicitNetworkDoctor.status, 0, explicitNetworkDoctor.stderr || explicitNetworkDoctor.stdout);
  const networkPayload = JSON.parse(explicitNetworkDoctor.stdout);
  assert.equal(networkPayload.network_requested, true);
  assert.equal(networkPayload.network_checks_performed, 0);
  assert.deepEqual(networkPayload.network_destinations, []);
  await traceAbsent(trace);

  const statusResult = execute(["status", ...common], trace);
  assert.equal(statusResult.status, 0, statusResult.stderr || statusResult.stdout);
  const statusPayload = JSON.parse(statusResult.stdout);
  assert.equal(statusPayload.connected_hosts, 0);
  assert.equal(statusPayload.queued_items, 0);
  await traceAbsent(trace);

  const repeated = execute(["init", ...common, "--recovery", "none", "--label", "test-agent"], trace);
  assert.equal(repeated.status, 0, repeated.stderr || repeated.stdout);
  assert.equal(JSON.parse(repeated.stdout).created, false);
  await traceAbsent(trace);

  const publicIdentity = await readFile(path.join(home, "identity", "identity.json"), "utf8");
  assert.doesNotMatch(publicIdentity, /private_key(?:_pkcs8)?|BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY/i);
  for (const file of await files(home)) {
    assert.doesNotMatch(path.basename(file), /\.(pem|key|p12|sqlite)$/i);
    if (path.basename(file) !== "keystore.blob") {
      const body = await readFile(file);
      assert.doesNotMatch(body.toString("utf8"), /BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY/);
    }
  }
});

test("observer tampering makes doctor fail closed without egress", async (context) => {
  const { home, trace } = await temporaryHome(context);
  const initialized = execute(["init", "--home", home, "--recovery", "none", "--json"], trace);
  assert.equal(initialized.status, 0, initialized.stderr || initialized.stdout);
  const configPath = path.join(home, "config", "config.json");
  const config = JSON.parse(await readFile(configPath, "utf8"));
  config.observer.status = "on";
  await writeFile(configPath, `${JSON.stringify(config, null, 2)}\n`, "utf8");
  const doctor = execute(["doctor", "--home", home, "--json"], trace);
  assert.equal(doctor.status, 7, doctor.stderr || doctor.stdout);
  assert.equal(JSON.parse(doctor.stdout).error, "OBSERVER_OFF_BASELINE_INVALID");
  await traceAbsent(trace);
});

test("missing recovery choice fails before state creation and without egress", async (context) => {
  const { home, trace } = await temporaryHome(context);
  const result = execute(["init", "--home", home, "--json"], trace);
  assert.equal(result.status, 2, result.stderr || result.stdout);
  assert.equal(JSON.parse(result.stdout).error, "RECOVERY_CHOICE_REQUIRED");
  await assert.rejects(stat(home), { code: "ENOENT" });
  await traceAbsent(trace);
});

test("unratified offline recovery fails before state creation", async (context) => {
  const { home, trace } = await temporaryHome(context);
  const result = execute(["init", "--home", home, "--recovery", "offline", "--json"], trace);
  assert.equal(result.status, 8, result.stderr || result.stdout);
  assert.equal(JSON.parse(result.stdout).error, "RECOVERY_PROFILE_UNAVAILABLE");
  await assert.rejects(stat(home), { code: "ENOENT" });
  await traceAbsent(trace);
});

test("relative alternate home is rejected before state creation", () => {
  const relative = `relative-home-forbidden-${process.pid}`;
  const result = execute(["init", "--home", relative, "--recovery", "none", "--json"], path.join(os.tmpdir(), `soma-network-relative-${process.pid}.trace`));
  assert.equal(result.status, 2, result.stderr || result.stdout);
  assert.equal(JSON.parse(result.stdout).error, "HOME_PATH_RELATIVE");
});

test("production modules contain no network client imports", async () => {
  const productionDirectories = [path.join(root, "src"), path.join(root, "bin")];
  for (const directory of productionDirectories) {
    for (const file of await files(directory)) {
      const source = await readFile(file, "utf8");
      assert.doesNotMatch(source, /node:(?:net|tls|http|https|http2|dns|dgram|quic)/);
      assert.doesNotMatch(source, /\bfetch\s*\(/);
    }
  }
});

test("unmanifested executable blocks initialization without egress", async (context) => {
  const { home, trace } = await temporaryHome(context);
  const unexpected = path.join(root, "bin", "__unexpected-test-executable.mjs");
  context.after(() => rm(unexpected, { force: true }));
  await writeFile(unexpected, "export default true;\\n", "utf8");
  let result;
  try {
    result = execute(["init", "--home", home, "--recovery", "none", "--json"], trace);
  } finally {
    await rm(unexpected, { force: true });
  }
  assert.equal(result.status, 4, result.stderr || result.stdout);
  assert.equal(JSON.parse(result.stdout).error, "RELEASE_FILE_SET_MISMATCH");
  await assert.rejects(stat(home), { code: "ENOENT" });
  await traceAbsent(trace);
});

test("home inside the release tree fails closed", () => {
  const result = execute(["init", "--home", path.join(root, "runtime", "forbidden"), "--recovery", "none", "--json"], path.join(os.tmpdir(), `soma-network-${process.pid}.trace`));
  assert.equal(result.status, 7, result.stderr || result.stdout);
  assert.equal(JSON.parse(result.stdout).error, "HOME_INSIDE_RELEASE");
});
