/**
 * Chain agent — breaks each probe into a planning step and an execution step.
 * Two Haiku calls per probe: first plans the approach, then executes it.
 * This produces distinct temporal signals (double latency, planning preamble)
 * and structural signals (the execution references the plan).
 */

import { streamHaiku, type AgentResponse } from "./base.js";

export async function runChain(prompt: string): Promise<AgentResponse> {
  // Step 1: Plan — ask Haiku to outline its approach
  const planResponse = await streamHaiku([
    {
      role: "system",
      content: "You are a planning assistant. Given a task, outline a brief plan (2-3 bullet points) for how to respond. Be concise — just the plan, no execution.",
    },
    { role: "user", content: prompt },
  ]);

  // Step 2: Execute — use the plan to produce the final response
  const execResponse = await streamHaiku([
    {
      role: "system",
      content: "You are a helpful assistant. Execute the following plan to answer the user's question. Follow the plan's structure but produce a complete, natural response.",
    },
    {
      role: "user",
      content: `Original question: ${prompt}\n\nPlan:\n${planResponse.text}`,
    },
  ]);

  // Merge traces — the phenotype includes BOTH calls
  const mergedTokens = [...planResponse.trace.tokens, ...execResponse.trace.tokens];
  const mergedTimestamps = [
    ...planResponse.trace.tokenTimestamps,
    ...execResponse.trace.tokenTimestamps,
  ];

  return {
    // Final text is the execution output (but the plan's phenotype is captured in timing)
    text: execResponse.text,
    trace: {
      tokens: mergedTokens,
      tokenTimestamps: mergedTimestamps,
      startTime: planResponse.trace.startTime,
      firstTokenTime: planResponse.trace.firstTokenTime,
      endTime: execResponse.trace.endTime,
    },
  };
}
