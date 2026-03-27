/**
 * Agent genome definitions for Phase 0 experiment.
 * Each config represents a distinct computational substrate — a unique "species."
 * Epigenetic variants share the same base model but differ in system prompt.
 * The proxy variant simulates an identity-theft attack.
 */

// --- Types ---

export type ProviderName = "groq" | "mistral" | "openrouter" | "anthropic" | "openai" | "ollama" | "google";

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
  family: "gemini" | "llama" | "gemma" | "mistral" | "deepseek" | "nvidia" | "stepfun" | "arcee" | "liquid" | "claude" | "gpt" | "qwen" | "phi";
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
    id: "liquid-lfm",
    label: "LFM 2.5 1.2B Instruct (OpenRouter)",
    provider: "openrouter",
    model: "liquid/lfm-2.5-1.2b-instruct:free",
    systemPrompt: DEFAULT_SYSTEM_PROMPT,
    family: "liquid",
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

  // --- OpenRouter (free tier — maximizing architectural diversity) ---
  {
    id: "gemini-flash",
    label: "Gemini 2.5 Flash (OpenRouter)",
    provider: "openrouter",
    model: "google/gemini-2.5-flash",
    systemPrompt: DEFAULT_SYSTEM_PROMPT,
    family: "gemini",
    isEpigenetic: false,
    isProxy: false,
    proxiedAgentId: null,
  },
  {
    id: "trinity-large",
    label: "Trinity Large Preview (OpenRouter)",
    provider: "openrouter",
    model: "arcee-ai/trinity-large-preview:free",
    systemPrompt: DEFAULT_SYSTEM_PROMPT,
    family: "arcee",
    isEpigenetic: false,
    isProxy: false,
    proxiedAgentId: null,
  },
  {
    id: "deepseek-v3",
    label: "DeepSeek V3 (OpenRouter)",
    provider: "openrouter",
    model: "deepseek/deepseek-v3.2-20251201",
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

  // --- Anthropic (Claude) ---
  {
    id: "claude-sonnet",
    label: "Claude Sonnet 4",
    provider: "anthropic",
    model: "claude-sonnet-4-20250514",
    systemPrompt: DEFAULT_SYSTEM_PROMPT,
    family: "claude",
    isEpigenetic: false,
    isProxy: false,
    proxiedAgentId: null,
  },
  {
    id: "claude-haiku",
    label: "Claude Haiku 4.5",
    provider: "anthropic",
    model: "claude-haiku-4-5-20251001",
    systemPrompt: DEFAULT_SYSTEM_PROMPT,
    family: "claude",
    isEpigenetic: false,
    isProxy: false,
    proxiedAgentId: null,
  },

  // --- OpenAI (GPT) ---
  {
    id: "gpt-4o",
    label: "GPT-4o",
    provider: "openai",
    model: "gpt-4o",
    systemPrompt: DEFAULT_SYSTEM_PROMPT,
    family: "gpt",
    isEpigenetic: false,
    isProxy: false,
    proxiedAgentId: null,
  },
  {
    id: "gpt-4o-mini",
    label: "GPT-4o Mini",
    provider: "openai",
    model: "gpt-4o-mini",
    systemPrompt: DEFAULT_SYSTEM_PROMPT,
    family: "gpt",
    isEpigenetic: false,
    isProxy: false,
    proxiedAgentId: null,
  },

  // --- Ollama Local (same hardware, different models — isolates model signal) ---
  {
    id: "ollama-llama3",
    label: "Llama 3.1 8B (Ollama local)",
    provider: "ollama",
    model: "llama3.1:8b",
    systemPrompt: DEFAULT_SYSTEM_PROMPT,
    family: "llama",
    isEpigenetic: false,
    isProxy: false,
    proxiedAgentId: null,
  },
  {
    id: "ollama-gemma2",
    label: "Gemma 2 9B (Ollama local)",
    provider: "ollama",
    model: "gemma2:9b",
    systemPrompt: DEFAULT_SYSTEM_PROMPT,
    family: "gemma",
    isEpigenetic: false,
    isProxy: false,
    proxiedAgentId: null,
  },
  {
    id: "ollama-qwen",
    label: "Qwen 2.5 7B (Ollama local)",
    provider: "ollama",
    model: "qwen2.5:7b",
    systemPrompt: DEFAULT_SYSTEM_PROMPT,
    family: "qwen",
    isEpigenetic: false,
    isProxy: false,
    proxiedAgentId: null,
  },
  {
    id: "ollama-mistral",
    label: "Mistral 7B (Ollama local)",
    provider: "ollama",
    model: "mistral:7b",
    systemPrompt: DEFAULT_SYSTEM_PROMPT,
    family: "mistral",
    isEpigenetic: false,
    isProxy: false,
    proxiedAgentId: null,
  },
  {
    id: "ollama-phi3",
    label: "Phi-3 Mini 3.8B (Ollama local)",
    provider: "ollama",
    model: "phi3:mini",
    systemPrompt: DEFAULT_SYSTEM_PROMPT,
    family: "phi",
    isEpigenetic: false,
    isProxy: false,
    proxiedAgentId: null,
  },

  // --- Google AI (Gemini free tier) ---
  {
    id: "gemini-flash-google",
    label: "Gemini 2.0 Flash (Google AI)",
    provider: "google",
    model: "gemini-2.0-flash",
    systemPrompt: DEFAULT_SYSTEM_PROMPT,
    family: "gemini",
    isEpigenetic: false,
    isProxy: false,
    proxiedAgentId: null,
  },

  // --- OpenRouter Free: deployment identity comparison ---
  {
    id: "or-llama3-8b",
    label: "Llama 3.1 8B (OpenRouter)",
    provider: "openrouter",
    model: "meta-llama/llama-3.1-8b-instruct:free",
    systemPrompt: DEFAULT_SYSTEM_PROMPT,
    family: "llama",
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
