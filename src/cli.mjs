import { createInterface } from "node:readline/promises";
import { stdin, stdout } from "node:process";
import { VERSION } from "./constants.mjs";
import { asSomaError, SomaError } from "./errors.mjs";
import { initialize, inspectState, resolveHome } from "./state.mjs";
import { recordEvidence, verifyAndRepairEvidence } from "./evidence.mjs";
import { observeStatus, previewObservation } from "./membrane.mjs";
import { expectedHostBindings, hostStatus, pinHostDescriptor, verifyHostDescriptorFile } from "./host.mjs";
import { hostSuccessionStatus, previewHostSuccession } from "./host-succession.mjs";
import { confirmHostSuccession, hostSuccessionHistoryStatus } from "./host-confirmation.mjs";
import { compareHostTrustCapsules, exportHostTrustCapsule, verifyHostTrustCapsuleFile } from "./host-trust-capsule.mjs";

function parse(argv) {
  const result = { command: null, options: {}, positionals: [] };
  for (let index = 0; index < argv.length; index += 1) {
    const token = argv[index];
    if (!result.command && !token.startsWith("-")) {
      result.command = token;
      continue;
    }
    if (token === "--json" || token === "--no-color" || token === "--network" || token === "--dev-insecure-file-keystore" || token === "--confirm-inert-pin-replacement") {
      result.options[token.slice(2).replaceAll("-", "_")] = true;
      continue;
    }
    if (["--home", "--label", "--recovery", "--input", "--artifact", "--evidence", "--policy", "--descriptor", "--expect-origin", "--expect-host-did", "--expect-network", "--expect-context", "--expect-key-hash", "--successor", "--proof", "--candidate-id", "--subject", "--expect-successor-descriptor", "--out", "--capsule", "--trusted", "--candidate", "--expect-controller-did", "--expect-controller-key-hash"].includes(token)) {
      const value = argv[index + 1];
      if (value === undefined || value.startsWith("--")) throw new SomaError(`${token} requires a value`, 2, "OPTION_VALUE_REQUIRED");
      result.options[token.slice(2).replaceAll("-", "_")] = value;
      index += 1;
      continue;
    }
    if (token === "--help" || token === "-h") result.options.help = true;
    else if (token === "--version" || token === "-v") result.options.version = true;
    else if (token.startsWith("-")) throw new SomaError(`unknown option: ${token}`, 2, "OPTION_UNKNOWN");
    else result.positionals.push(token);
  }
  return result;
}

function help() {
  return `Soma reference ${VERSION}\n\nUsage:\n  soma init [--home PATH] [--label TEXT] --recovery none [--json]\n  soma doctor [--home PATH] [--network] [--json]\n  soma status [--home PATH] [--json]\n  soma evidence record --input ABSOLUTE_EVENT.json [--home PATH] [--json]\n  soma evidence verify [--home PATH] [--json]\n  soma host status [--home PATH] [--json]\n  soma host verify --descriptor ABSOLUTE_DESCRIPTOR.json --expect-origin ORIGIN --expect-host-did DID --expect-network NETWORK --expect-context CONTEXT [--expect-key-hash HASH] [--home PATH] [--json]\n  soma host pin --descriptor ABSOLUTE_DESCRIPTOR.json --expect-origin ORIGIN --expect-host-did DID --expect-network NETWORK --expect-context CONTEXT --expect-key-hash HASH [--home PATH] [--json]\n  soma host succession-preview --successor ABSOLUTE_DESCRIPTOR.json --proof ABSOLUTE_PROOF.json [--home PATH] [--json]\n  soma host succession-confirm --candidate-id HASH --subject HASH --expect-successor-descriptor HASH --confirm-inert-pin-replacement [--home PATH] [--json]\n  soma host trust-export --out ABSOLUTE_CAPSULE.json [--home PATH] [--json]\n  soma host trust-verify --capsule ABSOLUTE_CAPSULE.json --expect-controller-did DID --expect-controller-key-hash HASH [--json]\n  soma host trust-compare --trusted TRUSTED_CAPSULE.json --candidate CANDIDATE_CAPSULE.json --expect-controller-did DID --expect-controller-key-hash HASH [--json]\n  soma observe status [--home PATH] [--json]\n  soma observe preview (--artifact ABSOLUTE_PATH | --evidence EVIDENCE_ID) --policy ABSOLUTE_POLICY.json [--home PATH] [--json]\n\nObservation preview is offline and creates no grant or send authority.\nEvidence is provisional, pre-network, self-signed attribution only. It is not truth, reputation, or independent rollback proof.\nObserver, telemetry, updates, retries, watchers, wallet, and token features are absent/off.`;
}

function print(value, json) {
  if (json) stdout.write(`${JSON.stringify(value)}\n`);
  else stdout.write(`${typeof value === "string" ? value : JSON.stringify(value, null, 2)}\n`);
}

async function recoveryChoice(options) {
  if (options.recovery) return options.recovery;
  if (!stdin.isTTY) throw new SomaError("recovery choice is required in non-interactive mode", 2, "RECOVERY_CHOICE_REQUIRED");
  const prompt = createInterface({ input: stdin, output: stdout });
  try {
    const answer = (await prompt.question("Recovery mode (none/offline): ")).trim().toLowerCase();
    if (!answer) throw new SomaError("recovery choice was not provided", 9, "RECOVERY_CHOICE_CANCELLED");
    return answer;
  } finally {
    prompt.close();
  }
}

export async function runCli(argv) {
  let parsed;
  try {
    parsed = parse(argv);
    if (parsed.options.version) {
      print(VERSION, parsed.options.json);
      return 0;
    }
    if (parsed.options.help || !parsed.command) {
      print(help(), parsed.options.json);
      return 0;
    }
    const home = resolveHome(parsed.options.home);
    if (parsed.command === "init") {
      if (parsed.positionals.length) throw new SomaError("unexpected positional arguments", 2, "POSITIONAL_ARGUMENT_UNEXPECTED");
      const result = await initialize({
        home,
        label: parsed.options.label ?? null,
        recovery: await recoveryChoice(parsed.options),
        allowInsecureDevelopment: parsed.options.dev_insecure_file_keystore === true
      });
      print({ ok: true, command: "init", ...result }, parsed.options.json);
      return 0;
    }
    if (parsed.command === "doctor") {
      if (parsed.positionals.length) throw new SomaError("unexpected positional arguments", 2, "POSITIONAL_ARGUMENT_UNEXPECTED");
      const result = await inspectState(home);
      print({
        ok: true,
        command: "doctor",
        offline: parsed.options.network !== true,
        network_requested: parsed.options.network === true,
        network_destinations: [],
        network_checks_performed: 0,
        home: result.home,
        release: result.release,
        permissions: result.permissions,
        free_bytes: result.free_bytes,
        prohibited_files: result.prohibited_files,
        ...result.summary
      }, parsed.options.json);
      return 0;
    }
    if (parsed.command === "status") {
      if (parsed.positionals.length) throw new SomaError("unexpected positional arguments", 2, "POSITIONAL_ARGUMENT_UNEXPECTED");
      const result = await inspectState(home);
      print({ ok: true, command: "status", home: result.home, release_version: result.release.release_version, ...result.summary }, parsed.options.json);
      return 0;
    }
    if (parsed.command === "evidence") {
      const action = parsed.positionals[0];
      if (!action || parsed.positionals.length !== 1 || !["record", "verify"].includes(action)) throw new SomaError("evidence requires exactly one action: record or verify", 2, "EVIDENCE_ACTION_INVALID");
      await inspectState(home, { verifyEvidence: false });
      if (action === "record") {
        if (!parsed.options.input) throw new SomaError("evidence record requires --input", 2, "EVIDENCE_INPUT_REQUIRED");
        const result = await recordEvidence(home, parsed.options.input);
        print({ ok: true, command: "evidence record", home, ...result }, parsed.options.json);
      } else {
        if (parsed.options.input) throw new SomaError("evidence verify does not accept --input", 2, "OPTION_NOT_ALLOWED");
        const result = await verifyAndRepairEvidence(home);
        print({ ok: true, command: "evidence verify", home, local_mutation: result.head_repaired || result.recovered_incomplete_tail_bytes > 0, remote_mutation: false, ...result }, parsed.options.json);
      }
      return 0;
    }
    if (parsed.command === "host") {
      const action = parsed.positionals[0];
      if (!action || parsed.positionals.length !== 1 || !["status", "verify", "pin", "succession-preview", "succession-confirm", "trust-export", "trust-verify", "trust-compare"].includes(action)) throw new SomaError("host requires exactly one action: status, verify, pin, succession-preview, succession-confirm, trust-export, trust-verify, or trust-compare", 2, "HOST_ACTION_INVALID");
      const allowed = {
        status: [],
        verify: ["descriptor", "expect_origin", "expect_host_did", "expect_network", "expect_context", "expect_key_hash"],
        pin: ["descriptor", "expect_origin", "expect_host_did", "expect_network", "expect_context", "expect_key_hash"],
        "succession-preview": ["successor", "proof"],
        "succession-confirm": ["candidate_id", "subject", "expect_successor_descriptor", "confirm_inert_pin_replacement"],
        "trust-export": ["out"],
        "trust-verify": ["capsule", "expect_controller_did", "expect_controller_key_hash"],
        "trust-compare": ["trusted", "candidate", "expect_controller_did", "expect_controller_key_hash"]
      };
      const common = new Set(["home", "json", "no_color"]);
      const unexpected = Object.keys(parsed.options).filter((key) => !common.has(key) && !allowed[action].includes(key));
      if (unexpected.length) throw new SomaError("host " + action + " does not accept " + unexpected.map((key) => "--" + key.replaceAll("_", "-")).join(", "), 2, "OPTION_NOT_ALLOWED");
      if (!["trust-verify", "trust-compare"].includes(action)) await inspectState(home);
      if (action === "trust-export") {
        if (!parsed.options.out) throw new SomaError("host trust-export requires --out", 2, "HOST_TRUST_CAPSULE_OUTPUT_REQUIRED");
        print({ ok: true, command: "host trust-export", home, ...(await exportHostTrustCapsule(home, parsed.options.out)) }, parsed.options.json);
      } else if (action === "trust-verify") {
        if (!parsed.options.capsule || !parsed.options.expect_controller_did || !parsed.options.expect_controller_key_hash) throw new SomaError("host trust-verify requires --capsule, --expect-controller-did, and --expect-controller-key-hash", 2, "HOST_TRUST_CAPSULE_VERIFY_INPUT_REQUIRED");
        print({ ok: true, command: "host trust-verify", ...(await verifyHostTrustCapsuleFile(parsed.options.capsule, { controllerDid: parsed.options.expect_controller_did, controllerKeyHash: parsed.options.expect_controller_key_hash })) }, parsed.options.json);
      } else if (action === "trust-compare") {
        if (!parsed.options.trusted || !parsed.options.candidate || !parsed.options.expect_controller_did || !parsed.options.expect_controller_key_hash) throw new SomaError("host trust-compare requires --trusted, --candidate, --expect-controller-did, and --expect-controller-key-hash", 2, "HOST_TRUST_CAPSULE_COMPARE_INPUT_REQUIRED");
        print({ ok: true, command: "host trust-compare", ...(await compareHostTrustCapsules(parsed.options.trusted, parsed.options.candidate, { controllerDid: parsed.options.expect_controller_did, controllerKeyHash: parsed.options.expect_controller_key_hash })) }, parsed.options.json);
      } else if (action === "status") {
        if (parsed.options.descriptor || parsed.options.successor || parsed.options.proof || parsed.options.candidate_id || parsed.options.subject || parsed.options.expect_successor_descriptor || parsed.options.confirm_inert_pin_replacement || parsed.options.expect_origin || parsed.options.expect_host_did || parsed.options.expect_network || parsed.options.expect_context || parsed.options.expect_key_hash) throw new SomaError("host status does not accept verification options", 2, "OPTION_NOT_ALLOWED");
        print({ ok: true, command: "host status", home, ...(await hostStatus(home)), ...(await hostSuccessionStatus(home)), ...(await hostSuccessionHistoryStatus(home)) }, parsed.options.json);
      } else if (action === "succession-preview") {
        if (parsed.options.descriptor || parsed.options.candidate_id || parsed.options.subject || parsed.options.expect_successor_descriptor || parsed.options.confirm_inert_pin_replacement || parsed.options.expect_origin || parsed.options.expect_host_did || parsed.options.expect_network || parsed.options.expect_context || parsed.options.expect_key_hash) throw new SomaError("host succession-preview accepts only --successor and --proof", 2, "OPTION_NOT_ALLOWED");
        if (!parsed.options.successor || !parsed.options.proof) throw new SomaError("host succession-preview requires --successor and --proof", 2, "HOST_SUCCESSION_INPUT_REQUIRED");
        print({ ok: true, command: "host succession-preview", home, ...(await previewHostSuccession(home, parsed.options.successor, parsed.options.proof)) }, parsed.options.json);
      } else if (action === "succession-confirm") {
        if (parsed.options.descriptor || parsed.options.successor || parsed.options.proof || parsed.options.expect_origin || parsed.options.expect_host_did || parsed.options.expect_network || parsed.options.expect_context || parsed.options.expect_key_hash) throw new SomaError("host succession-confirm accepts only exact confirmation identifiers and the explicit replacement flag", 2, "OPTION_NOT_ALLOWED");
        const result = await confirmHostSuccession(home, { candidateId: parsed.options.candidate_id, subjectId: parsed.options.subject, successorDescriptorId: parsed.options.expect_successor_descriptor, confirmInertPinReplacement: parsed.options.confirm_inert_pin_replacement === true });
        print({ ok: true, command: "host succession-confirm", home, ...result }, parsed.options.json);
      } else {
        if (parsed.options.successor || parsed.options.proof || parsed.options.candidate_id || parsed.options.subject || parsed.options.expect_successor_descriptor || parsed.options.confirm_inert_pin_replacement) throw new SomaError(`host ${action} does not accept succession options`, 2, "OPTION_NOT_ALLOWED");
        if (!parsed.options.descriptor) throw new SomaError(`host ${action} requires --descriptor`, 2, "HOST_DESCRIPTOR_REQUIRED");
        const expected = expectedHostBindings(parsed.options);
        const result = action === "verify" ? await verifyHostDescriptorFile(parsed.options.descriptor, expected) : await pinHostDescriptor(home, parsed.options.descriptor, expected);
        print({ ok: true, command: `host ${action}`, home, ...result }, parsed.options.json);
      }
      return 0;
    }
    if (parsed.command === "observe") {
      const action = parsed.positionals[0];
      if (!action || parsed.positionals.length !== 1 || !["status", "preview"].includes(action)) throw new SomaError("observe requires exactly one action: status or preview", 2, "OBSERVE_ACTION_INVALID");
      await inspectState(home);
      if (action === "status") {
        if (parsed.options.artifact || parsed.options.evidence || parsed.options.policy) throw new SomaError("observe status does not accept preview options", 2, "OPTION_NOT_ALLOWED");
        print({ ok: true, command: "observe status", home, ...(await observeStatus(home)), local_mutation: false, remote_mutation: false }, parsed.options.json);
      } else {
        if (!parsed.options.policy) throw new SomaError("observe preview requires --policy", 2, "PREVIEW_POLICY_REQUIRED");
        const result = await previewObservation(home, { policyFile: parsed.options.policy, artifactFile: parsed.options.artifact ?? null, evidenceId: parsed.options.evidence ?? null });
        print({ ok: true, command: "observe preview", home, ...result }, parsed.options.json);
      }
      return 0;
    }
    throw new SomaError(`unknown command: ${parsed.command}`, 2, "COMMAND_UNKNOWN");
  } catch (error) {
    const failure = asSomaError(error);
    const payload = {
      ok: false,
      error: failure.code,
      message: failure.message,
      local_mutation: failure.details?.local_mutation === true,
      remote_mutation: failure.details?.remote_mutation === true,
      ...(failure.details ? { details: failure.details } : {})
    };
    if (parsed?.options?.json) process.stdout.write(`${JSON.stringify(payload)}\n`);
    else process.stderr.write(`${failure.code}: ${failure.message}\n`);
    return failure.exitCode;
  }
}
