import { describe, it, expect } from "vitest";
import {
  extractToolInteractionSignals,
  toolInteractionToFeatureVector,
  TOOL_INTERACTION_FEATURE_NAMES,
} from "../../src/sensorium/senses/tool-interaction.js";

describe("Tool Interaction (Sense 4)", () => {
  it("returns -1 defaults for non-tool agents", () => {
    const signals = extractToolInteractionSignals(
      "Here is my answer without tools.",
      "normal",
      false
    );
    expect(signals.toolCallRate).toBe(-1);
    expect(signals.toolCallEagerness).toBe(-1);
    expect(signals.toolResultIntegration).toBe(-1);
    expect(signals.toolChainDepth).toBe(-1);
    expect(signals.toolSelectionEntropy).toBe(-1);
    expect(signals.toolVsManualRatio).toBe(-1);
  });

  it("detects tool call presence", () => {
    const withTool = extractToolInteractionSignals(
      "Let me use the search tool to find that information.",
      "normal",
      true
    );
    const withoutTool = extractToolInteractionSignals(
      "Here is the answer based on my knowledge.",
      "normal",
      true
    );
    expect(withTool.toolCallRate).toBe(1);
    expect(withoutTool.toolCallRate).toBe(0);
  });

  it("measures tool call eagerness (early vs late)", () => {
    const eager = extractToolInteractionSignals(
      "Let me call the API. Here is some text after the tool call.",
      "normal",
      true
    );
    const late = extractToolInteractionSignals(
      "First let me think about this problem carefully. There are many considerations. Let me call the API.",
      "normal",
      true
    );
    expect(eager.toolCallEagerness).toBeLessThan(late.toolCallEagerness);
  });

  it("detects tool result integration", () => {
    const integrated = extractToolInteractionSignals(
      "Let me use the search tool. Based on the result, the output shows that the data is correct.",
      "normal",
      true
    );
    expect(integrated.toolResultIntegration).toBe(1);
  });

  it("detects manual math computation", () => {
    const manual = extractToolInteractionSignals(
      "Let me calculate: step 1, first multiply 5 * 3 = 15.",
      "normal",
      true
    );
    expect(manual.toolVsManualRatio).toBe(0);
  });

  it("produces a feature vector of correct length", () => {
    const signals = extractToolInteractionSignals("Test.", "normal", true);
    const vector = toolInteractionToFeatureVector(signals);
    expect(vector.length).toBe(TOOL_INTERACTION_FEATURE_NAMES.length);
    expect(vector.length).toBe(6);
  });
});
