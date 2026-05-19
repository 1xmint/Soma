/**
 * Phenotypic signal extraction from MCP messages.
 *
 * Adapts the Phase 0 signal extractors for MCP's message format.
 * MCP messages are complete JSON-RPC responses — no token-level streaming.
 * Temporal signals come from message-level timing instead.
 *
 * Like observing an animal's behavior through a window — you see the
 * complete actions, not the individual muscle twitches. Still phenotypic.
 */

import {
  extractCognitiveSignals,
  extractStructuralSignals,
  extractErrorSignals,
  type PhenotypicSignals,
  type StreamingTrace,
} from "../experiment/signals.js";
import type { JSONRPCMessage } from "@modelcontextprotocol/sdk/types.js";

// --- Types ---

interface MessageTiming {
  /** When the request was received (performance.now). */
  requestTime: number;
  /** When the response was sent (performance.now). */
  responseTime: number;
}

interface MessageAccumulator {
  /** Accumulated response timings for inter-message interval computation. */
  responseTimes: number[];
}

// --- Text Extraction from MCP Messages ---

/**
 * Extract readable text content from a JSON-RPC message.
 * MCP responses carry text in tool results, resource contents,
 * prompt completions, and error messages.
 */
export function extractTextFromMessage(message: JSONRPCMessage): string | null {
  if (!("result" in message) || !message.result) return null;

  const result = message.result as Record<string, unknown>;
  const parts: string[] = [];

  // Tool call results: { content: [{ type: "text", text: "..." }] }
  if (Array.isArray(result.content)) {
    for (const item of result.content) {
      if (typeof item === "object" && item !== null && "text" in item) {
        parts.push(String((item as Record<string, unknown>).text));
      }
    }
  }

  // Resource read results: { contents: [{ text: "..." }] }
  if (Array.isArray(result.contents)) {
    for (const item of result.contents) {
      if (typeof item === "object" && item !== null && "text" in item) {
        parts.push(String((item as Record<string, unknown>).text));
      }
    }
  }

  // Prompt get results: { messages: [{ content: { text: "..." } }] }
  if (Array.isArray(result.messages)) {
    for (const msg of result.messages) {
      const m = msg as Record<string, unknown>;
      if (typeof m.content === "object" && m.content !== null && "text" in m.content) {
        parts.push(String((m.content as Record<string, unknown>).text));
      } else if (typeof m.content === "string") {
        parts.push(m.content);
      }
    }
  }

  // Completion results: { completion: { values: [...] } }
  if (result.completion && typeof result.completion === "object") {
    const comp = result.completion as Record<string, unknown>;
    if (Array.isArray(comp.values)) {
      parts.push(...comp.values.map(String));
    }
  }

  return parts.length > 0 ? parts.join("\n") : null;
}

/**
 * Infer a probe category from the MCP method — used by error signal extraction.
 * In the experiment we knew the category. In live traffic we infer it.
 */
function inferCategory(message: JSONRPCMessage): string {
  if ("error" in message) return "failure";
  if ("method" in message) {
    const method = message.method;
    if (method === "tools/call") return "normal";
    if (method === "prompts/get") return "normal";
    if (method === "resources/read") return "normal";
  }
  return "normal";
}

// --- Signal Tap ---

export class SignalTap {
  private accumulator: MessageAccumulator = { responseTimes: [] };

  /**
   * Extract phenotypic signals from a response message and its timing.
   * Returns null if the message has no extractable text content.
   */
  tap(message: JSONRPCMessage, timing: MessageTiming): PhenotypicSignals | null {
    const text = extractTextFromMessage(message);
    if (!text || text.length < 5) return null;

    const category = inferCategory(message);

    // Cognitive and structural — reuse Phase 0 extractors directly
    const cognitive = extractCognitiveSignals(text);
    const structural = extractStructuralSignals(text);
    const error = extractErrorSignals(text, category);

    // Temporal — adapted from message-level timing (coarser than token-level)
    const latency = timing.responseTime - timing.requestTime;
    this.accumulator.responseTimes.push(timing.responseTime);

    // Compute inter-message intervals from accumulated response times
    const intervals: number[] = [];
    const times = this.accumulator.responseTimes;
    for (let i = 1; i < times.length; i++) {
      intervals.push(times[i] - times[i - 1]);
    }

    let meanInterval = 0;
    let stdInterval = 0;
    let medianInterval = 0;
    let burstiness = 0;

    if (intervals.length > 0) {
      meanInterval = intervals.reduce((a, b) => a + b, 0) / intervals.length;
      const variance = intervals.reduce((sum, v) => sum + (v - meanInterval) ** 2, 0) / intervals.length;
      stdInterval = Math.sqrt(variance);
      const sorted = [...intervals].sort((a, b) => a - b);
      const mid = Math.floor(sorted.length / 2);
      medianInterval = sorted.length % 2 === 0
        ? (sorted[mid - 1] + sorted[mid]) / 2
        : sorted[mid];
      burstiness = meanInterval === 0 ? 0 : variance / meanInterval;
    }

    // Estimate token count from word count (rough approximation)
    const words = text.split(/\s+/).filter(Boolean);
    const estimatedTokens = Math.round(words.length * 1.3);

    const temporal = {
      timeToFirstToken: latency,
      interTokenIntervals: intervals,
      meanInterval,
      stdInterval,
      medianInterval,
      burstiness,
      totalStreamingDuration: latency,
      tokenCount: estimatedTokens,
    };

    return { cognitive, structural, temporal, error };
  }

  /** Reset accumulated state (e.g., on new session). */
  reset(): void {
    this.accumulator = { responseTimes: [] };
  }
}
