/**
 * Agent genome definitions for Phase 0 experiment.
 * Each config represents a distinct computational substrate — a unique "species."
 * Epigenetic variants share the same base model but differ in system prompt.
 * The proxy variant simulates an identity-theft attack.
 */

// --- Types ---

export type ProviderName = "google" | "groq" | "mistral" | "openrouter";

export interface AgentConfig {
  /** Unique identifier for this genome in experiment results. */
  id: string;
  /** Human-readable label. */
  label: string;
  /** API provider to route requests through. */
  provider: ProviderName;
  /** Model identifier as the provider's API expects it. */
  model: string;
  /** System prompt — the epigenetic layer that shapes expression. */
  systemPrompt: string;
  /** Model family for family-level classification. */
  family: "gemini" | "llama" | "mixtral" | "gemma" | "mistral" | "deepseek" | "nvidia" | "stepfun";
  /** Whether this is an epigenetic variant (same model, different prompt). */
  isEpigenetic: boolean;
  /** Whether this genome is a proxy attack simulation. */
  isProxy: boolean;
  /** If proxy, the ID of the real agent being impersonated. */
  proxiedAgentId: string | null;
}

// --- System Prompts ---

const DEFAULT_SYSTEM_PROMPT = "You are a helpful assistant.";

const FORMAL_SYSTEM_PROMPT = `You are a distinguished academic research assistant.
Communicate with precise, formal language. Use technical terminology where appropriate.
Structure responses with clear logical progression. Cite principles and frameworks.
Avoid colloquialisms, contractions, and casual phrasing.
Maintain an authoritative, measured tone throughout.`;

const CHAOTIC_SYSTEM_PROMPT = `You are a wildly creative, stream-of-consciousness assistant!
Think sideways. Mix metaphors freely. Use unexpected analogies.
Jump between ideas with enthusiasm!! Embrace tangents and digressions.
Use varied punctuation... dashes — ellipses... exclamation marks!
Be playful, irreverent, and surprising in your responses.`;

// --- Agent Genome Definitions ---

export const AGENT_CONFIGS: AgentConfig[] = [
  // --- Google AI Studio ---
  {
    id: "gemini-flash",
    label: "Gemini 2.0 Flash",
    provider: "google",
    model: "gemini-2.0-flash",
    systemPrompt: DEFAULT_SYSTEM_PROMPT,
    family: "gemini",
    isEpigenetic: false,
    isProxy: false,
    proxiedAgentId: null,
  },
  {
    id: "gemini-pro",
    label: "Gemini 1.5 Pro",
    provider: "google",
    model: "gemini-1.5-pro",
    systemPrompt: DEFAULT_SYSTEM_PROMPT,
    family: "gemini",
    isEpigenetic: false,
    isProxy: false,
    proxiedAgentId: null,
  },

  // --- Groq ---
  {
    id: "llama3-70b",
    label: "Llama 3.3 70B (Groq)",
    provider: "groq",
    model: "llama-3.3-70b-versatile",
    systemPrompt: DEFAULT_SYSTEM_PROMPT,
    family: "llama",
    isEpigenetic: false,
    isProxy: false,
    proxiedAgentId: null,
  },
  {
    id: "llama3-8b",
    label: "Llama 3.1 8B (Groq)",
    provider: "groq",
    model: "llama-3.1-8b-instant",
    systemPrompt: DEFAULT_SYSTEM_PROMPT,
    family: "llama",
    isEpigenetic: false,
    isProxy: false,
    proxiedAgentId: null,
  },
  {
    id: "mixtral",
    label: "Mixtral 8x7B (Groq)",
    provider: "groq",
    model: "mixtral-8x7b-32768",
    systemPrompt: DEFAULT_SYSTEM_PROMPT,
    family: "mixtral",
    isEpigenetic: false,
    isProxy: false,
    proxiedAgentId: null,
  },
  {
    id: "gemma2",
    label: "Gemma 2 9B (Groq)",
    provider: "groq",
    model: "gemma2-9b-it",
    systemPrompt: DEFAULT_SYSTEM_PROMPT,
    family: "gemma",
    isEpigenetic: false,
    isProxy: false,
    proxiedAgentId: null,
  },

  // --- Mistral ---
  {
    id: "mistral-small",
    label: "Mistral Small",
    provider: "mistral",
    model: "mistral-small-latest",
    systemPrompt: DEFAULT_SYSTEM_PROMPT,
    family: "mistral",
    isEpigenetic: false,
    isProxy: false,
    proxiedAgentId: null,
  },

  // --- OpenRouter (free tier — new model families for architectural diversity) ---
  {
    id: "deepseek-v3",
    label: "DeepSeek V3 (OpenRouter)",
    provider: "openrouter",
    model: "deepseek/deepseek-chat:free",
    systemPrompt: DEFAULT_SYSTEM_PROMPT,
    family: "deepseek",
    isEpigenetic: false,
    isProxy: false,
    proxiedAgentId: null,
  },
  {
    id: "nemotron-super",
    label: "Nemotron 3 Super 120B (OpenRouter)",
    provider: "openrouter",
    model: "nvidia/nemotron-3-super-120b-a12b:free",
    systemPrompt: DEFAULT_SYSTEM_PROMPT,
    family: "nvidia",
    isEpigenetic: false,
    isProxy: false,
    proxiedAgentId: null,
  },
  {
    id: "step-flash",
    label: "Step 3.5 Flash (OpenRouter)",
    provider: "openrouter",
    model: "stepfun/step-3.5-flash:free",
    systemPrompt: DEFAULT_SYSTEM_PROMPT,
    family: "stepfun",
    isEpigenetic: false,
    isProxy: false,
    proxiedAgentId: null,
  },

  // --- Epigenetic Variants (same DNA, different expression) ---
  {
    id: "llama3-70b-formal",
    label: "Llama 3.3 70B — Formal (Epigenetic)",
    provider: "groq",
    model: "llama-3.3-70b-versatile",
    systemPrompt: FORMAL_SYSTEM_PROMPT,
    family: "llama",
    isEpigenetic: true,
    isProxy: false,
    proxiedAgentId: null,
  },
  {
    id: "llama3-70b-chaotic",
    label: "Llama 3.3 70B — Chaotic (Epigenetic)",
    provider: "groq",
    model: "llama-3.3-70b-versatile",
    systemPrompt: CHAOTIC_SYSTEM_PROMPT,
    family: "llama",
    isEpigenetic: true,
    isProxy: false,
    proxiedAgentId: null,
  },

  // --- Proxy Attack Simulation (identity theft attempt) ---
  {
    id: "proxy-llama3-70b",
    label: "Proxy → Llama 3.3 70B (Attack Simulation)",
    provider: "groq",
    model: "llama-3.3-70b-versatile",
    systemPrompt: DEFAULT_SYSTEM_PROMPT,
    family: "llama",
    isEpigenetic: false,
    isProxy: true,
    proxiedAgentId: "llama3-70b",
  },
];

/** Look up an agent config by ID. */
export function getAgentConfig(id: string): AgentConfig {
  const config = AGENT_CONFIGS.find((c) => c.id === id);
  if (!config) throw new Error(`Unknown agent config: ${id}`);
  return config;
}
