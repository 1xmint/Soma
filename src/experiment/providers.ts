/**
 * Streaming API clients for each provider.
 *
 * Every call streams token-by-token so we capture the temporal phenotype —
 * the model's "heartbeat." Without streaming, we'd only get total latency,
 * which is like judging an animal's species by how long it takes to cross
 * a field instead of watching its gait.
 */

import OpenAI from "openai";
import type { StreamingTrace } from "./signals.js";
import type { ProviderName } from "./configs.js";
import type { TokenLogprob } from "../sensorium/stream-capture.js";

// --- Types ---

export interface StreamingResponse {
  text: string;
  trace: StreamingTrace;
  /** Logprob data for each token (null if API doesn't support it). */
  logprobs: TokenLogprob[] | null;
  /** Indices where new network chunks started. */
  chunkBoundaries: number[];
  /** Provider-specific metadata (e.g., Groq timing stats). */
  providerMeta: Record<string, unknown>;
}

// --- Key Pool (rate-limit rotation) ---

interface KeyPool {
  keys: string[];
  currentIndex: number;
  exhausted: Set<number>;
}

const keyPools = new Map<ProviderName, KeyPool>();

/**
 * Build a key pool from environment variables.
 * Tries the base key name, then _2, _3, _4, etc.
 */
function getKeyPool(provider: ProviderName): KeyPool {
  if (keyPools.has(provider)) return keyPools.get(provider)!;

  const envNames: Record<ProviderName, string[]> = {
    groq: ["GROQ_API_KEY", "GROQ_API_KEY_2", "GROQ_API_KEY_3"],
    openrouter: ["OPENROUTER_API_KEY", "OPENROUTER_API_KEY_2", "OPENROUTER_API_KEY_3", "OPENROUTER_API_KEY_4", "OPENROUTER_API_KEY_5"],
    mistral: ["MISTRAL_API_KEY"],
    anthropic: ["ANTHROPIC_API_KEY"],
    openai: ["OPENAI_API_KEY"],
    ollama: [],
    google: ["GOOGLE_AI_API_KEY", "GOOGLE_AI_API_KEY_1"],
  };

  const keys: string[] = [];
  for (const name of envNames[provider]) {
    const val = process.env[name];
    if (val) keys.push(val);
  }

  if (keys.length === 0 && provider !== "ollama") {
    throw new Error(`No API keys found for provider: ${provider}. Set ${envNames[provider][0]} in .env`);
  }

  const pool: KeyPool = { keys, currentIndex: 0, exhausted: new Set() };
  keyPools.set(provider, pool);
  return pool;
}

/** Get the current key for a provider. Throws if all keys exhausted. */
function getCurrentKey(provider: ProviderName): string {
  const pool = getKeyPool(provider);
  if (pool.exhausted.size >= pool.keys.length) {
    throw new Error(`All ${pool.keys.length} API keys for ${provider} are rate-limited`);
  }
  return pool.keys[pool.currentIndex];
}

/** Get the environment variable name for a key index. */
function getKeyEnvName(provider: ProviderName, index: number): string {
  const baseName = provider.toUpperCase() + "_API_KEY";
  return index === 0 ? baseName : `${baseName}_${index + 1}`;
}

/** Rotate to the next available key after a 429/402. Returns true if a key was available. */
function rotateKey(provider: ProviderName): boolean {
  const pool = getKeyPool(provider);
  const exhaustedName = getKeyEnvName(provider, pool.currentIndex);
  pool.exhausted.add(pool.currentIndex);

  // Find next non-exhausted key
  for (let i = 0; i < pool.keys.length; i++) {
    const idx = (pool.currentIndex + 1 + i) % pool.keys.length;
    if (!pool.exhausted.has(idx)) {
      pool.currentIndex = idx;
      const newName = getKeyEnvName(provider, idx);
      console.log(`  [KEY ROTATION] Switched to ${newName} after rate limit on ${exhaustedName}`);
      return true;
    }
  }

  console.log(`  [KEY ROTATION] ${provider}: all ${pool.keys.length} keys exhausted`);
  return false;
}

/** Reset exhaustion state for a provider (call between experiment runs). */
export function resetKeyPool(provider?: ProviderName): void {
  if (provider) {
    const pool = keyPools.get(provider);
    if (pool) pool.exhausted.clear();
  } else {
    for (const pool of keyPools.values()) pool.exhausted.clear();
  }
}

// --- Provider Clients ---

const PROVIDER_BASE_URLS: Record<ProviderName, string> = {
  groq: "https://api.groq.com/openai/v1",
  mistral: "https://api.mistral.ai/v1",
  openrouter: "https://openrouter.ai/api/v1",
  anthropic: "https://api.anthropic.com/v1",
  openai: "https://api.openai.com/v1",
  ollama: "http://localhost:11434/v1",
  google: "https://generativelanguage.googleapis.com/v1beta/openai",
};

/** Per-call timeout in milliseconds. */
const CALL_TIMEOUT_MS = 60_000;

/**
 * Route a prompt to the appropriate provider and stream the response.
 * Automatically rotates API keys on 429 rate-limit errors.
 * Aborts any call that takes longer than 60 seconds.
 * All providers return a StreamingResponse with token-level timing.
 */
export async function streamFromProvider(
  provider: ProviderName,
  model: string,
  systemPrompt: string,
  userPrompt: string
): Promise<StreamingResponse> {
  const baseURL = PROVIDER_BASE_URLS[provider];

  // Ollama: no API key, no rotation — local server
  if (provider === "ollama") {
    return await withTimeout(
      streamFromOpenAICompatible(baseURL, "ollama", model, systemPrompt, userPrompt),
      CALL_TIMEOUT_MS,
      `${provider}/${model} timed out after ${CALL_TIMEOUT_MS / 1000}s`
    );
  }

  const pool = getKeyPool(provider);
  const maxAttempts = pool.keys.length;

  for (let attempt = 0; attempt < maxAttempts; attempt++) {
    const apiKey = getCurrentKey(provider);
    try {
      return await withTimeout(
        streamFromOpenAICompatible(baseURL, apiKey, model, systemPrompt, userPrompt),
        CALL_TIMEOUT_MS,
        `${provider}/${model} timed out after ${CALL_TIMEOUT_MS / 1000}s`
      );
    } catch (err: unknown) {
      if (isRateLimitError(err)) {
        const rotated = rotateKey(provider);
        if (!rotated) {
          throw new Error(`All ${pool.keys.length} API keys for ${provider} are rate-limited`);
        }
        // Brief pause before retrying with the next key
        await new Promise((r) => setTimeout(r, 2000));
        continue;
      }
      throw err;
    }
  }

  throw new Error(`All ${maxAttempts} API keys for ${provider} are rate-limited`);
}

/** Wrap a promise with a timeout. Rejects with TimeoutError if it takes too long. */
function withTimeout<T>(promise: Promise<T>, ms: number, message: string): Promise<T> {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error(message)), ms);
    promise.then(
      (val) => { clearTimeout(timer); resolve(val); },
      (err) => { clearTimeout(timer); reject(err); },
    );
  });
}

/** Check if an error is a rate-limit (429) or quota-exceeded (402) response. */
function isRateLimitError(err: unknown): boolean {
  if (err && typeof err === "object") {
    // OpenAI SDK throws APIError with status
    if ("status" in err) {
      const status = (err as { status: number }).status;
      if (status === 429 || status === 402) return true;
    }
    // Some providers include it in the message
    if ("message" in err && typeof (err as { message: string }).message === "string") {
      const msg = (err as { message: string }).message.toLowerCase();
      if (msg.includes("rate limit") || msg.includes("429") || msg.includes("too many requests")
        || msg.includes("quota") || msg.includes("402") || msg.includes("insufficient")) {
        return true;
      }
    }
  }
  return false;
}

// --- OpenAI-Compatible (Groq, Mistral, OpenRouter) ---
// All use the OpenAI SDK with custom baseURL.

// Track which baseURL+model combos reject logprobs so we don't retry every call
const logprobsBlacklist = new Set<string>();

async function streamFromOpenAICompatible(
  baseURL: string,
  apiKey: string,
  model: string,
  systemPrompt: string,
  userPrompt: string,
  forceNoLogprobs = false
): Promise<StreamingResponse> {
  const client = new OpenAI({ baseURL, apiKey, timeout: CALL_TIMEOUT_MS });

  const startTime = performance.now();
  let firstTokenTime: number | null = null;
  const tokens: string[] = [];
  const tokenTimestamps: number[] = [];
  const logprobs: TokenLogprob[] = [];
  const chunkBoundaries: number[] = [];
  let hasLogprobs = false;
  let lastChunkTime = -1;
  const providerMeta: Record<string, unknown> = { provider: baseURL, model };

  // Only request logprobs if the provider/model hasn't rejected them before
  const logprobsKey = `${baseURL}|${model}`;
  const tryLogprobs = !forceNoLogprobs
    && !baseURL.includes("anthropic.com")
    && !logprobsBlacklist.has(logprobsKey);

  let stream;
  try {
    stream = await client.chat.completions.create({
      model,
      messages: [
        { role: "system", content: systemPrompt },
        { role: "user", content: userPrompt },
      ],
      stream: true,
      ...(tryLogprobs ? { logprobs: true, top_logprobs: 5 } : {}),
    });
  } catch (err: unknown) {
    // If logprobs caused a 400, blacklist and retry without them
    if (tryLogprobs && err && typeof err === "object" && "status" in err
        && (err as { status: number }).status === 400) {
      logprobsBlacklist.add(logprobsKey);
      return streamFromOpenAICompatible(baseURL, apiKey, model, systemPrompt, userPrompt, true);
    }
    throw err;
  }

  // Consume stream with a per-chunk stall timeout.
  // On Windows, SSE connections sometimes don't close cleanly,
  // causing `for await` to hang after the last chunk. This watchdog
  // aborts the stream if no chunk arrives within 15 seconds.
  const CHUNK_STALL_MS = 15_000;
  let stallTimer: ReturnType<typeof setTimeout> | null = null;
  const resetStallTimer = () => {
    if (stallTimer) clearTimeout(stallTimer);
    stallTimer = setTimeout(() => {
      try { stream.controller.abort(); } catch {}
    }, CHUNK_STALL_MS);
  };

  resetStallTimer();
  try {
    for await (const chunk of stream) {
      resetStallTimer();
      const now = performance.now();
      const choice = chunk.choices[0];
      const content = choice?.delta?.content;

      if (content) {
        if (firstTokenTime === null) firstTokenTime = now;

        // Chunk boundary detection: if gap > 0.5ms from last recorded token, new chunk
        if (lastChunkTime < 0 || (now - lastChunkTime) > 0.5) {
          chunkBoundaries.push(tokens.length);
        }

        tokens.push(content);
        tokenTimestamps.push(now);
        lastChunkTime = now;

        // Capture logprob data if available
        const lpData = choice?.logprobs?.content;
        if (lpData && Array.isArray(lpData)) {
          for (const lp of lpData) {
            hasLogprobs = true;
            logprobs.push({
              token: lp.token ?? content,
              logprob: lp.logprob ?? 0,
              topAlternatives: (lp.top_logprobs ?? []).map(
                (alt: { token: string; logprob: number }) => ({
                  token: alt.token,
                  logprob: alt.logprob,
                })
              ),
            });
          }
        }
      }

      // Capture Groq-specific timing metadata from the final chunk
      const usage = chunk.usage as
        | (OpenAI.CompletionUsage & {
            queue_time?: number;
            prompt_time?: number;
            completion_time?: number;
          })
        | undefined;
      if (usage) {
        if (usage.queue_time !== undefined) providerMeta.queueTime = usage.queue_time;
        if (usage.prompt_time !== undefined) providerMeta.promptTime = usage.prompt_time;
        if (usage.completion_time !== undefined) providerMeta.completionTime = usage.completion_time;
      }
    }
  } catch (err: unknown) {
    // AbortError from stall timer is expected — stream completed, connection hung
    if (!(err && typeof err === "object" && "name" in err && (err as {name: string}).name === "AbortError")) {
      // Only re-throw if we got zero tokens (real failure vs stale connection)
      if (tokens.length === 0) throw err;
    }
  } finally {
    if (stallTimer) clearTimeout(stallTimer);
  }

  const endTime = performance.now();

  return {
    text: tokens.join(""),
    trace: { tokenTimestamps, tokens, startTime, firstTokenTime, endTime },
    logprobs: hasLogprobs ? logprobs : null,
    chunkBoundaries,
    providerMeta,
  };
}

// --- Proxy Attack Simulation ---

/**
 * Simulates a proxy forwarding attack. Sends the request to the real
 * Llama 3.3 70B on Groq but adds realistic variable network latency.
 *
 * The response CONTENT is identical (it IS the real agent). Only the
 * timing changes — each token gets an extra delay sampled from a
 * log-normal distribution simulating a real network hop.
 *
 * Can the sensorium detect this from timing artifacts alone?
 */
export async function streamThroughProxy(
  systemPrompt: string,
  userPrompt: string
): Promise<StreamingResponse> {
  // Get the real response through the provider (with key rotation)
  const real = await streamFromProvider(
    "groq",
    "llama-3.3-70b-versatile",
    systemPrompt,
    userPrompt
  );

  // Inject realistic proxy latency into the timing trace.
  // Log-normal distribution: mean ~15ms, std ~8ms per hop.
  const proxyTrace = injectProxyLatency(real.trace);

  return {
    text: real.text,
    trace: proxyTrace,
    logprobs: real.logprobs,
    chunkBoundaries: real.chunkBoundaries,
    providerMeta: { ...real.providerMeta, proxied: true },
  };
}

/**
 * Sample from a log-normal distribution.
 * Given desired mean and std in linear space, converts to log-space parameters.
 */
function sampleLogNormal(mean: number, std: number): number {
  const variance = std * std;
  const mu = Math.log(mean * mean / Math.sqrt(variance + mean * mean));
  const sigma = Math.sqrt(Math.log(1 + variance / (mean * mean)));

  // Box-Muller transform for normal sample
  const u1 = Math.random();
  const u2 = Math.random();
  const z = Math.sqrt(-2 * Math.log(u1)) * Math.cos(2 * Math.PI * u2);

  return Math.exp(mu + sigma * z);
}

/**
 * Inject simulated proxy network latency into a streaming trace.
 * Each token gets an independent latency sample — no fixed delay.
 */
function injectProxyLatency(original: StreamingTrace): StreamingTrace {
  // A real proxy adds ONE network hop per token — the token travels
  // from the real model → proxy → observer. Each token gets its own
  // independent latency sample, but the delays are NOT cumulative.
  // Token N arrives at: original_time[N] + hop_delay[N].
  //
  // The initial connection also has a handshake delay added to all timestamps.
  const handshakeDelay = sampleLogNormal(15, 8);
  const newTimestamps: number[] = [];

  for (let i = 0; i < original.tokenTimestamps.length; i++) {
    const hopDelay = sampleLogNormal(15, 8);
    newTimestamps.push(original.tokenTimestamps[i] + handshakeDelay + hopDelay);
  }

  // Ensure monotonicity — a later token can't arrive before an earlier one
  for (let i = 1; i < newTimestamps.length; i++) {
    if (newTimestamps[i] < newTimestamps[i - 1]) {
      newTimestamps[i] = newTimestamps[i - 1] + 0.1;
    }
  }

  const newFirstToken =
    original.firstTokenTime !== null
      ? newTimestamps[0] ?? original.firstTokenTime + handshakeDelay
      : null;

  const lastTimestamp = newTimestamps[newTimestamps.length - 1] ?? original.endTime;
  const endTime = Math.max(lastTimestamp, original.endTime + handshakeDelay);

  return {
    ...original,
    tokenTimestamps: newTimestamps,
    firstTokenTime: newFirstToken,
    endTime,
  };
}

