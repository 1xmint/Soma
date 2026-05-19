/**
 * RAG agent — retrieves context from a local corpus before each call.
 * Same Haiku, but every response is grounded in retrieved documents.
 * This should produce different structural and cognitive signals:
 * more citations, more grounded language, fewer hedges.
 */

import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { streamHaiku, type AgentResponse } from "./base.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const CORPUS = readFileSync(join(__dirname, "rag-corpus.txt"), "utf-8");

/** Simple retrieval: find the most relevant paragraph for the query. */
function retrieve(query: string): string {
  const paragraphs = CORPUS.split("\n\n").filter((p) => p.trim().length > 20);
  const queryWords = new Set(query.toLowerCase().split(/\s+/));

  // Score paragraphs by word overlap
  const scored = paragraphs.map((p) => {
    const words = p.toLowerCase().split(/\s+/);
    const overlap = words.filter((w) => queryWords.has(w)).length;
    return { text: p, score: overlap };
  });

  scored.sort((a, b) => b.score - a.score);
  // Return top 2 paragraphs as context
  return scored.slice(0, 2).map((s) => s.text).join("\n\n");
}

export async function runRag(prompt: string): Promise<AgentResponse> {
  const context = retrieve(prompt);

  return streamHaiku([
    {
      role: "system",
      content: `You are a helpful assistant. Answer questions using the following reference material. If the reference material is not relevant to the question, answer from your general knowledge but note that you're doing so.\n\nReference material:\n${context}`,
    },
    { role: "user", content: prompt },
  ]);
}
