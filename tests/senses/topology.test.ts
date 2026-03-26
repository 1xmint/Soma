import { describe, it, expect } from "vitest";
import {
  extractTopologySignals,
  topologyToFeatureVector,
  TOPOLOGY_FEATURE_NAMES,
} from "../../src/sensorium/senses/topology.js";

describe("Response Topology (Sense 2)", () => {
  it("computes paragraph length variance", () => {
    // Two paragraphs: ~5 words and ~20 words — high variance
    const high = extractTopologySignals(
      "Short paragraph here.\n\n" +
      "This is a much longer paragraph that contains many more words to create a significant difference in length."
    );
    // Two paragraphs of similar length — low variance
    const low = extractTopologySignals(
      "First paragraph has five words.\n\n" +
      "Second paragraph has five words."
    );
    expect(high.topoParagraphLengthVariance).toBeGreaterThan(low.topoParagraphLengthVariance);
  });

  it("computes paragraph length trend (slope)", () => {
    // Paragraphs get longer → positive slope
    const increasing = extractTopologySignals(
      "Short.\n\nA bit longer paragraph.\n\nThis is a significantly longer paragraph with many words."
    );
    // Paragraphs get shorter → negative slope
    const decreasing = extractTopologySignals(
      "This is a significantly longer paragraph with many words.\n\nA bit longer paragraph.\n\nShort."
    );
    expect(increasing.topoParagraphLengthTrend).toBeGreaterThan(0);
    expect(decreasing.topoParagraphLengthTrend).toBeLessThan(0);
  });

  it("computes transition density", () => {
    const withTransitions = extractTopologySignals(
      "First, we consider the problem.\n\n" +
      "However, there are alternatives.\n\n" +
      "Finally, we reach a conclusion."
    );
    const withoutTransitions = extractTopologySignals(
      "The problem is clear.\n\n" +
      "There are alternatives.\n\n" +
      "We reach a conclusion."
    );
    expect(withTransitions.topoTransitionDensity).toBeGreaterThan(withoutTransitions.topoTransitionDensity);
  });

  it("computes topic coherence via Jaccard similarity", () => {
    // Consecutive paragraphs about the same topic — high coherence
    const coherent = extractTopologySignals(
      "Machine learning algorithms process data efficiently.\n\n" +
      "These algorithms learn from data to improve predictions."
    );
    // Completely different topics — low coherence
    const incoherent = extractTopologySignals(
      "Machine learning algorithms process data efficiently.\n\n" +
      "The ancient Romans built impressive aqueducts across Europe."
    );
    expect(coherent.topoTopicCoherence).toBeGreaterThan(incoherent.topoTopicCoherence);
  });

  it("computes frontloading ratio", () => {
    // First paragraph is most of the content
    const frontloaded = extractTopologySignals(
      "This is a very long first paragraph with lots and lots of words and detailed explanations about the topic at hand.\n\n" +
      "Short ending."
    );
    // First paragraph is tiny
    const backloaded = extractTopologySignals(
      "Brief intro.\n\n" +
      "This is a very long second paragraph with lots and lots of words and detailed explanations about the topic at hand."
    );
    expect(frontloaded.topoFrontloadingRatio).toBeGreaterThan(backloaded.topoFrontloadingRatio);
  });

  it("detects list position", () => {
    const earlyList = extractTopologySignals(
      "- Item 1\n- Item 2\n\nSome text follows the list."
    );
    const lateList = extractTopologySignals(
      "Some text before the list.\n\n- Item 1\n- Item 2"
    );
    const noList = extractTopologySignals(
      "No lists here. Just plain text paragraphs."
    );
    expect(earlyList.topoListPosition).toBeGreaterThanOrEqual(0);
    expect(earlyList.topoListPosition).toBeLessThan(lateList.topoListPosition);
    expect(noList.topoListPosition).toBe(-1);
  });

  it("detects conclusion presence", () => {
    const withConclusion = extractTopologySignals(
      "Some content here.\n\nIn summary, this covers the key points."
    );
    const withoutConclusion = extractTopologySignals(
      "Some content here.\n\nHere are more details about the topic."
    );
    expect(withConclusion.topoConclusionPresent).toBe(1);
    expect(withoutConclusion.topoConclusionPresent).toBe(0);
  });

  it("computes nesting depth from headers", () => {
    const deep = extractTopologySignals(
      "# Title\n\n## Section\n\n### Subsection\n\n#### Deep section\n\nContent here."
    );
    const flat = extractTopologySignals(
      "Just a flat paragraph with no headers or structure at all."
    );
    expect(deep.topoNestingDepth).toBeGreaterThanOrEqual(4);
    expect(flat.topoNestingDepth).toBe(0);
  });

  it("computes nesting depth from indented lists", () => {
    const nested = extractTopologySignals(
      "- Item 1\n  - Sub-item\n    - Sub-sub-item"
    );
    expect(nested.topoNestingDepth).toBeGreaterThanOrEqual(2);
  });

  it("detects code block position", () => {
    const earlyCode = extractTopologySignals(
      "```js\nconsole.log('hi');\n```\n\nSome text after code."
    );
    const lateCode = extractTopologySignals(
      "Some text before code.\n\n```js\nconsole.log('hi');\n```"
    );
    const noCode = extractTopologySignals(
      "No code blocks here at all."
    );
    expect(earlyCode.topoCodePosition).toBeGreaterThanOrEqual(0);
    expect(earlyCode.topoCodePosition).toBeLessThan(lateCode.topoCodePosition);
    expect(noCode.topoCodePosition).toBe(-1);
  });

  it("handles empty text gracefully", () => {
    const signals = extractTopologySignals("");
    expect(signals.topoParagraphLengthVariance).toBe(0);
    expect(signals.topoParagraphLengthTrend).toBe(0);
    expect(signals.topoTransitionDensity).toBe(0);
    expect(signals.topoTopicCoherence).toBe(0);
    expect(signals.topoFrontloadingRatio).toBe(0);
    expect(signals.topoListPosition).toBe(-1);
    expect(signals.topoConclusionPresent).toBe(0);
    expect(signals.topoNestingDepth).toBe(0);
    expect(signals.topoCodePosition).toBe(-1);
  });

  it("produces a feature vector of correct length", () => {
    const signals = extractTopologySignals("Hello world.\n\nAnother paragraph.");
    const vector = topologyToFeatureVector(signals);
    expect(vector.length).toBe(TOPOLOGY_FEATURE_NAMES.length);
    expect(vector.length).toBe(9);
    for (const v of vector) {
      expect(typeof v).toBe("number");
      expect(isNaN(v)).toBe(false);
    }
  });

  it("distinguishes structured from unstructured responses", () => {
    const structured = extractTopologySignals(
      "# Overview\n\nFirst, let's consider the problem.\n\n" +
      "## Details\n\n- Point A\n- Point B\n- Point C\n\n" +
      "## Code Example\n\n```python\nprint('hello')\n```\n\n" +
      "In summary, this covers everything."
    );
    const unstructured = extractTopologySignals(
      "Well I think the answer is pretty simple. " +
      "You just need to think about it differently. " +
      "There are a few things to consider but nothing too complex."
    );
    // Structured should have deeper nesting, transitions, conclusion
    expect(structured.topoNestingDepth).toBeGreaterThan(unstructured.topoNestingDepth);
    expect(structured.topoConclusionPresent).toBe(1);
    expect(structured.topoCodePosition).toBeGreaterThanOrEqual(0);
    expect(unstructured.topoCodePosition).toBe(-1);
  });
});
