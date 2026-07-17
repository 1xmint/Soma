import { createInterface } from "node:readline/promises";
import { stdin, stdout } from "node:process";
import { VERSION } from "./constants.mjs";
import { asSomaError, SomaError } from "./errors.mjs";
import { initialize, inspectState, resolveHome } from "./state.mjs";

function parse(argv) {
  const result = { command: null, options: {}, positionals: [] };
  for (let index = 0; index < argv.length; index += 1) {
    const token = argv[index];
    if (!result.command && !token.startsWith("-")) {
      result.command = token;
      continue;
    }
    if (token === "--json" || token === "--no-color" || token === "--network" || token === "--dev-insecure-file-keystore") {
      result.options[token.slice(2).replaceAll("-", "_")] = true;
      continue;
    }
    if (["--home", "--label", "--recovery"].includes(token)) {
      const value = argv[index + 1];
      if (value === undefined || value.startsWith("--")) throw new SomaError(`${token} requires a value`, 2, "OPTION_VALUE_REQUIRED");
      result.options[token.slice(2)] = value;
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
  return `Soma reference ${VERSION}\n\nUsage:\n  soma init [--home PATH] [--label TEXT] --recovery none [--json]\n  soma doctor [--home PATH] [--network] [--json]\n  soma status [--home PATH] [--json]\n\nObserver, telemetry, updates, retries, watchers, wallet, and token features are absent/off.`;
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
    if (parsed.positionals.length) throw new SomaError("unexpected positional arguments", 2, "POSITIONAL_ARGUMENT_UNEXPECTED");
    const home = resolveHome(parsed.options.home);
    if (parsed.command === "init") {
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
      const result = await inspectState(home);
      const destinations = [];
      print({
        ok: true,
        command: "doctor",
        offline: parsed.options.network !== true,
        network_requested: parsed.options.network === true,
        network_destinations: destinations,
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
      const result = await inspectState(home);
      print({ ok: true, command: "status", home: result.home, release_version: result.release.release_version, ...result.summary }, parsed.options.json);
      return 0;
    }
    throw new SomaError(`unknown command: ${parsed.command}`, 2, "COMMAND_UNKNOWN");
  } catch (error) {
    const failure = asSomaError(error);
    const payload = {
      ok: false,
      error: failure.code,
      message: failure.message,
      local_mutation: false,
      remote_mutation: false,
      ...(failure.details ? { details: failure.details } : {})
    };
    if (parsed?.options?.json) process.stdout.write(`${JSON.stringify(payload)}\n`);
    else process.stderr.write(`${failure.code}: ${failure.message}\n`);
    return failure.exitCode;
  }
}
