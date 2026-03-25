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

// --- Types ---

export interface StreamingResponse {
  text: string;
  trace: StreamingTrace;
  /** Provider-specific metadata (e.g., Groq timing stats). */
  providerMeta: Record<string, unknown>;
}

// --- Provider Clients ---

/**
 * Route a prompt to the appropriate provider and stream the response.
 * All providers return a StreamingResponse with token-level timing.
 */
export async function streamFromProvider(
  provider: ProviderName,
  model: string,
  systemPrompt: string,
  userPrompt: string
): Promise<StreamingResponse> {
  switch (provider) {
    case "groq":
      return streamFromOpenAICompatible(
        "https://api.groq.com/openai/v1",
        getEnvKey("GROQ_API_KEY"),
        model,
        systemPrompt,
        userPrompt
      );
    case "mistral":
      return streamFromOpenAICompatible(
        "https://api.mistral.ai/v1",
        getEnvKey("MISTRAL_API_KEY"),
        model,
        systemPrompt,
        userPrompt
      );
    case "openrouter":
      return streamFromOpenAICompatible(
        "https://openrouter.ai/api/v1",
        getEnvKey("OPENROUTER_API_KEY"),
        model,
        systemPrompt,
        userPrompt
      );
    case "anthropic":
      return streamFromOpenAICompatible(
        "https://api.anthropic.com/v1",
        getEnvKey("ANTHROPIC_API_KEY"),
        model,
        systemPrompt,
        userPrompt
      );
    case "openai":
      return streamFromOpenAICompatible(
        "https://api.openai.com/v1",
        getEnvKey("OPENAI_API_KEY"),
        model,
        systemPrompt,
        userPrompt
      );
  }
}

// --- OpenAI-Compatible (Groq, Mistral, OpenRouter) ---
// All use the OpenAI SDK with custom baseURL.

async function streamFromOpenAICompatible(
  baseURL: string,
  apiKey: string,
  model: string,
  systemPrompt: string,
  userPrompt: string
): Promise<StreamingResponse> {
  const client = new OpenAI({ baseURL, apiKey });

  const startTime = performance.now();
  let firstTokenTime: number | null = null;
  const tokens: string[] = [];
  const tokenTimestamps: number[] = [];
  const providerMeta: Record<string, unknown> = { provider: baseURL, model };

  const stream = await client.chat.completions.create({
    model,
    messages: [
      { role: "system", content: systemPrompt },
      { role: "user", content: userPrompt },
    ],
    stream: true,
  });

  for await (const chunk of stream) {
    const content = chunk.choices[0]?.delta?.content;
    if (content) {
      const now = performance.now();
      if (firstTokenTime === null) firstTokenTime = now;
      tokens.push(content);
      tokenTimestamps.push(now);
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

  const endTime = performance.now();

  return {
    text: tokens.join(""),
    trace: { tokenTimestamps, tokens, startTime, firstTokenTime, endTime },
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
  // Get the real response from the actual model
  const real = await streamFromOpenAICompatible(
    "https://api.groq.com/openai/v1",
    getEnvKey("GROQ_API_KEY"),
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

// --- Helpers ---

function getEnvKey(name: string): string {
  const value = process.env[name];
  if (!value) {
    throw new Error(
      `Missing environment variable: ${name}. Add it to your .env file.`
    );
  }
  return value;
}
