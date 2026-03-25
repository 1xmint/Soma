/**
 * Bare agent — raw Haiku with no tools, no context, no framing.
 * The control group. Pure LLM phenotype with zero agent overhead.
 */

import { streamHaiku, type AgentResponse } from "./base.js";

export async function runBare(prompt: string): Promise<AgentResponse> {
  return streamHaiku([
    { role: "system", content: "You are a helpful assistant." },
    { role: "user", content: prompt },
  ]);
}
