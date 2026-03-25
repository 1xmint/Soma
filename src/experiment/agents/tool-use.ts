/**
 * Tool-use agent — Haiku with calculator and string tools.
 * The model can choose to call tools, producing a different response
 * pattern: tool call blocks, structured outputs, multi-turn reasoning.
 * This changes both structural signals (tool call formatting) and
 * temporal signals (extra roundtrips for tool execution).
 */

import { getClient, HAIKU_MODEL, type AgentResponse } from "./base.js";

const TOOLS: Array<{
  type: "function";
  function: { name: string; description: string; parameters: Record<string, unknown> };
}> = [
  {
    type: "function",
    function: {
      name: "calculator",
      description: "Evaluate a mathematical expression. Use this for any arithmetic.",
      parameters: {
        type: "object",
        properties: {
          expression: { type: "string", description: "Math expression to evaluate, e.g. '2 + 2 * 3'" },
        },
        required: ["expression"],
      },
    },
  },
  {
    type: "function",
    function: {
      name: "string_length",
      description: "Count the number of characters in a string.",
      parameters: {
        type: "object",
        properties: {
          text: { type: "string", description: "The string to measure" },
        },
        required: ["text"],
      },
    },
  },
  {
    type: "function",
    function: {
      name: "reverse_string",
      description: "Reverse a string.",
      parameters: {
        type: "object",
        properties: {
          text: { type: "string", description: "The string to reverse" },
        },
        required: ["text"],
      },
    },
  },
];

/** Execute a tool call locally. */
function executeTool(name: string, args: Record<string, string>): string {
  switch (name) {
    case "calculator":
      try {
        // Safe math eval using Function constructor with no globals
        const result = new Function(`"use strict"; return (${args.expression})`)();
        return String(result);
      } catch {
        return "Error: invalid expression";
      }
    case "string_length":
      return String(args.text?.length ?? 0);
    case "reverse_string":
      return [...(args.text ?? "")].reverse().join("");
    default:
      return "Unknown tool";
  }
}

export async function runToolUse(prompt: string): Promise<AgentResponse> {
  const client = getClient();
  const startTime = performance.now();
  let firstTokenTime: number | null = null;
  const tokens: string[] = [];
  const tokenTimestamps: number[] = [];

  const messages: Array<Record<string, unknown>> = [
    { role: "system", content: "You are a helpful assistant with access to tools. Use them when appropriate." },
    { role: "user", content: prompt },
  ];

  // First call — may include tool calls
  const stream1 = await client.chat.completions.create({
    model: HAIKU_MODEL,
    messages: messages as Parameters<typeof client.chat.completions.create>[0]["messages"],
    tools: TOOLS,
    stream: true,
  });

  let toolCalls: Array<{ id: string; name: string; arguments: string }> = [];
  let currentToolCall: { id: string; name: string; arguments: string } | null = null;

  for await (const chunk of stream1) {
    const delta = chunk.choices[0]?.delta;
    if (delta?.content) {
      const now = performance.now();
      if (firstTokenTime === null) firstTokenTime = now;
      tokens.push(delta.content);
      tokenTimestamps.push(now);
    }
    // Accumulate tool calls from streaming deltas
    if (delta?.tool_calls) {
      for (const tc of delta.tool_calls) {
        if (tc.id) {
          if (currentToolCall) toolCalls.push(currentToolCall);
          currentToolCall = { id: tc.id, name: tc.function?.name ?? "", arguments: "" };
        }
        if (tc.function?.arguments && currentToolCall) {
          currentToolCall.arguments += tc.function.arguments;
        }
      }
    }
  }
  if (currentToolCall) toolCalls.push(currentToolCall);

  // If there were tool calls, execute them and do a follow-up call
  if (toolCalls.length > 0) {
    // Add assistant message with tool calls
    messages.push({
      role: "assistant",
      content: tokens.join("") || null,
      tool_calls: toolCalls.map((tc) => ({
        id: tc.id,
        type: "function",
        function: { name: tc.name, arguments: tc.arguments },
      })),
    });

    // Add tool results
    for (const tc of toolCalls) {
      let args: Record<string, string> = {};
      try { args = JSON.parse(tc.arguments); } catch { /* empty */ }
      const result = executeTool(tc.name, args);
      messages.push({ role: "tool", tool_call_id: tc.id, content: result });
    }

    // Follow-up call with tool results
    const stream2 = await client.chat.completions.create({
      model: HAIKU_MODEL,
      messages: messages as Parameters<typeof client.chat.completions.create>[0]["messages"],
      tools: TOOLS,
      stream: true,
    });

    for await (const chunk of stream2) {
      const content = chunk.choices[0]?.delta?.content;
      if (content) {
        const now = performance.now();
        if (firstTokenTime === null) firstTokenTime = now;
        tokens.push(content);
        tokenTimestamps.push(now);
      }
    }
  }

  const endTime = performance.now();
  return {
    text: tokens.join(""),
    trace: { tokenTimestamps, tokens, startTime, firstTokenTime, endTime },
  };
}
