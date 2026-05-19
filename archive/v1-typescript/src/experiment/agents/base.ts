/**
 * Shared base for agent-level phenotype testing.
 * All agents use Claude Haiku — the base LLM is constant.
 * Only the agent architecture varies.
 */

import OpenAI from "openai";
import type { StreamingTrace } from "../signals.js";

let client: OpenAI | null = null;

export function getClient(): OpenAI {
  if (!client) {
    client = new OpenAI({
      baseURL: "https://api.anthropic.com/v1",
      apiKey: process.env.ANTHROPIC_API_KEY!,
    });
  }
  return client;
}

export const HAIKU_MODEL = "claude-haiku-4-5-20251001";

export interface AgentResponse {
  text: string;
  trace: StreamingTrace;
}

/** Stream a single Haiku call and capture token-level timing. */
export async function streamHaiku(
  messages: Array<{ role: "system" | "user" | "assistant"; content: string }>,
): Promise<AgentResponse> {
  const c = getClient();
  const startTime = performance.now();
  let firstTokenTime: number | null = null;
  const tokens: string[] = [];
  const tokenTimestamps: number[] = [];

  const stream = await c.chat.completions.create({
    model: HAIKU_MODEL,
    messages,
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
  }

  const endTime = performance.now();
  return {
    text: tokens.join(""),
    trace: { tokenTimestamps, tokens, startTime, firstTokenTime, endTime },
  };
}
