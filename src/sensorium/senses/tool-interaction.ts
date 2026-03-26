/**
 * Sense 4: Tool Interaction
 *
 * Measures tool usage patterns — how eagerly the agent reaches for tools,
 * how deeply it chains them, how it integrates results. Only meaningful
 * for tool-using agents; all features default to -1 for non-tool agents.
 */

// --- Types ---

export interface ToolInteractionSignals {
  toolCallRate: number;
  toolCallEagerness: number;
  toolResultIntegration: number;
  toolChainDepth: number;
  toolSelectionEntropy: number;
  toolVsManualRatio: number;
}

// --- Patterns ---

const TOOL_CALL_INDICATORS = [
  /\btool_call\b/i,
  /\bfunction_call\b/i,
  /\b<tool>/i,
  /\bcalling (?:the )?\w+ tool\b/i,
  /\busing (?:the )?\w+ tool\b/i,
  /\blet me (?:use|call|invoke|run)\b/i,
  /\bI'll (?:use|call|invoke|run)\b/i,
];

const TOOL_NAME_RE = /\b(?:tool|function)(?:_call)?:\s*(\w+)/gi;

const MATH_TOOL_RE = /\b(?:calculator|compute|eval|python|code_interpreter|wolfram)\b/i;
const MANUAL_MATH_RE = /\b(?:let me calculate|step \d|first,? multiply|= \d|\d+\s*[+\-*/]\s*\d+\s*=)\b/i;

// --- Helpers ---

function shannonEntropy(items: string[]): number {
  if (items.length === 0) return 0;
  const counts = new Map<string, number>();
  for (const item of items) {
    counts.set(item, (counts.get(item) ?? 0) + 1);
  }
  let entropy = 0;
  for (const count of counts.values()) {
    const p = count / items.length;
    if (p > 0) entropy -= p * Math.log2(p);
  }
  return entropy;
}

// --- Main Extractor ---

export function extractToolInteractionSignals(
  text: string,
  category: string,
  hasTools: boolean = false
): ToolInteractionSignals {
  // All default to -1 for non-tool agents
  if (!hasTools) {
    return {
      toolCallRate: -1,
      toolCallEagerness: -1,
      toolResultIntegration: -1,
      toolChainDepth: -1,
      toolSelectionEntropy: -1,
      toolVsManualRatio: -1,
    };
  }

  const totalChars = text.length;

  // --- Tool call detection ---
  let hasToolCall = false;
  let firstToolPos = totalChars;
  for (const pattern of TOOL_CALL_INDICATORS) {
    const match = text.match(pattern);
    if (match && match.index !== undefined) {
      hasToolCall = true;
      if (match.index < firstToolPos) firstToolPos = match.index;
    }
  }

  // --- Tool call rate (for this response: 0 or 1) ---
  const toolCallRate = hasToolCall ? 1 : 0;

  // --- Tool call eagerness (position of first tool indicator) ---
  const toolCallEagerness = hasToolCall ? firstToolPos / Math.max(totalChars, 1) : -1;

  // --- Tool result integration ---
  // Check if post-tool text references tool-like results
  let toolResultIntegration = 0;
  if (hasToolCall && firstToolPos < totalChars) {
    const postTool = text.slice(firstToolPos);
    // Look for phrases that integrate results
    const integrationPatterns = [
      /\b(?:the result|the output|this shows|this gives|we can see|according to the|based on)\b/i,
      /\b(?:returned|yielded|produced|found|showed|indicates)\b/i,
    ];
    toolResultIntegration = integrationPatterns.some((p) => p.test(postTool)) ? 1 : 0;
  }

  // --- Tool chain depth (sequential tool uses) ---
  const toolMentions = [...text.matchAll(/\b(?:tool|function)(?:_call)?/gi)];
  const toolChainDepth = toolMentions.length;

  // --- Tool selection entropy ---
  const toolNames: string[] = [];
  for (const m of text.matchAll(TOOL_NAME_RE)) {
    if (m[1]) toolNames.push(m[1].toLowerCase());
  }
  const toolSelectionEntropy = shannonEntropy(toolNames);

  // --- Tool vs manual ratio (for math probes) ---
  let toolVsManualRatio = -1;
  if (category === "normal" || category === "edge_case") {
    const usesTool = MATH_TOOL_RE.test(text);
    const usesManual = MANUAL_MATH_RE.test(text);
    if (usesTool && !usesManual) toolVsManualRatio = 1;
    else if (!usesTool && usesManual) toolVsManualRatio = 0;
    else if (usesTool && usesManual) toolVsManualRatio = 0.5;
    // else stays -1
  }

  return {
    toolCallRate,
    toolCallEagerness,
    toolResultIntegration,
    toolChainDepth,
    toolSelectionEntropy,
    toolVsManualRatio,
  };
}

/** Feature names for the tool interaction sense. */
export const TOOL_INTERACTION_FEATURE_NAMES: string[] = [
  "tool_call_rate",
  "tool_call_eagerness",
  "tool_result_integration",
  "tool_chain_depth",
  "tool_selection_entropy",
  "tool_vs_manual_ratio",
];

/** Convert tool interaction signals to a numeric feature vector. */
export function toolInteractionToFeatureVector(
  signals: ToolInteractionSignals
): number[] {
  return [
    signals.toolCallRate,
    signals.toolCallEagerness,
    signals.toolResultIntegration,
    signals.toolChainDepth,
    signals.toolSelectionEntropy,
    signals.toolVsManualRatio,
  ];
}
