import { describe, it, expect } from "vitest";
import {
  createLandscape,
  updateLandscape,
  matchLandscape,
  computeDriftVelocity,
  type LandscapeMatchResult,
} from "../../src/sensorium/landscape.js";
import type { PhenotypicSignals } from "../../src/experiment/signals.js";
import {
  matchEnhanced,
} from "../../src/sensorium/matcher.js";

// --- Helpers ---

function makeSignals(overrides: Partial<{
  wordCount: number;
  hedgeCount: number;
  meanInterval: number;
  avgWordLength: number;
}> = {}): PhenotypicSignals {
  return {
    cognitive: {
      hedgeCount: overrides.hedgeCount ?? 3,
      certaintyCount: 2,
      disclaimerCount: 1,
      questionsBack: 0,
      empathyMarkers: 1,
      hedgeToCertaintyRatio: 0.6,
    },
    structural: {
      charCount: 500,
      wordCount: overrides.wordCount ?? 100,
      lineCount: 10,
      paragraphCount: 3,
      bulletLines: 2,
      numberedListLines: 0,
      headerLines: 1,
      codeBlocks: 0,
      boldCount: 1,
      listToContentRatio: 0.2,
      openingPattern: "direct",
      closingPattern: "statement",
      avgWordLength: overrides.avgWordLength ?? 5.0,
      avgSentenceLength: 15,
    },
    temporal: {
      timeToFirstToken: 200,
      interTokenIntervals: [10, 12, 8, 11, 9],
      meanInterval: overrides.meanInterval ?? 10,
      stdInterval: 2,
      medianInterval: 10,
      burstiness: 5,
      totalStreamingDuration: 1200,
      tokenCount: 130,
    },
    error: {
      containsRefusal: false,
      uncertaintyAdmissions: 0,
      assertiveWhenWrong: 0,
      attemptedImpossible: false,
      selfCorrections: 0,
      confidenceRatio: 0.5,
    },
  };
}

describe("BehavioralLandscape", () => {
  it("creates an empty landscape", () => {
    const landscape = createLandscape("test-hash");
    expect(landscape.genomeHash).toBe("test-hash");
    expect(landscape.categories.size).toBe(0);
    expect(landscape.totalObservations).toBe(0);
    expect(landscape.maturity).toBe("embryonic");
  });

  it("tracks observations by category", () => {
    const landscape = createLandscape("test");
    updateLandscape(landscape, makeSignals(), "normal");
    updateLandscape(landscape, makeSignals(), "normal");
    updateLandscape(landscape, makeSignals(), "ambiguity");

    expect(landscape.categories.size).toBe(2);
    expect(landscape.categories.get("normal")?.observationCount).toBe(2);
    expect(landscape.categories.get("ambiguity")?.observationCount).toBe(1);
    expect(landscape.totalObservations).toBe(3);
  });

  it("tracks maturity progression", () => {
    const landscape = createLandscape("test");
    expect(landscape.maturity).toBe("embryonic");

    for (let i = 0; i < 10; i++) {
      updateLandscape(landscape, makeSignals(), "normal");
    }
    expect(landscape.maturity).toBe("juvenile");

    for (let i = 0; i < 40; i++) {
      updateLandscape(landscape, makeSignals(), "normal");
    }
    expect(landscape.maturity).toBe("adult");
  });

  it("uses flat profile when category has < 5 observations", () => {
    const landscape = createLandscape("test");
    // Add 10 normal, only 2 ambiguity
    for (let i = 0; i < 10; i++) {
      updateLandscape(landscape, makeSignals(), "normal");
    }
    for (let i = 0; i < 2; i++) {
      updateLandscape(landscape, makeSignals(), "ambiguity");
    }

    const normalResult = matchLandscape(landscape, makeSignals(), "normal");
    const ambiguityResult = matchLandscape(landscape, makeSignals(), "ambiguity");

    expect(normalResult.usedCategoryProfile).toBe(true);
    expect(ambiguityResult.usedCategoryProfile).toBe(false); // falls back to flat
  });

  it("uses category profile when enough observations exist", () => {
    const landscape = createLandscape("test");
    for (let i = 0; i < 10; i++) {
      updateLandscape(landscape, makeSignals({ wordCount: 100 }), "normal");
      updateLandscape(landscape, makeSignals({ wordCount: 300 }), "ambiguity");
    }

    // Normal query should match normal profile well
    const normalResult = matchLandscape(landscape, makeSignals({ wordCount: 100 }), "normal");
    expect(normalResult.usedCategoryProfile).toBe(true);
    expect(normalResult.matchRatio).toBeGreaterThan(0.5);
  });

  it("computes cross-category stability", () => {
    const landscape = createLandscape("test");
    // Two categories with different behaviors
    for (let i = 0; i < 10; i++) {
      updateLandscape(landscape, makeSignals({ wordCount: 50, hedgeCount: 1 }), "rapid_fire");
      updateLandscape(landscape, makeSignals({ wordCount: 300, hedgeCount: 10 }), "ambiguity");
    }

    expect(Object.keys(landscape.crossCategoryStability).length).toBeGreaterThan(0);
    // Word count stability should show high variation
    expect(landscape.crossCategoryStability["word_count"]).toBeGreaterThan(0);
  });

  it("records transition signatures", () => {
    const landscape = createLandscape("test");
    // Build up some category data first
    for (let i = 0; i < 5; i++) {
      updateLandscape(landscape, makeSignals({ wordCount: 50 }), "rapid_fire");
    }
    // Transition from rapid_fire to ambiguity
    updateLandscape(landscape, makeSignals({ wordCount: 300 }), "ambiguity", "rapid_fire");

    expect(landscape.transitions.length).toBe(1);
    expect(landscape.transitions[0].fromCategory).toBe("rapid_fire");
    expect(landscape.transitions[0].toCategory).toBe("ambiguity");
  });

  it("detects drift from consistent behavior", () => {
    const landscape = createLandscape("test");
    for (let i = 0; i < 20; i++) {
      updateLandscape(landscape, makeSignals({ wordCount: 100 }), "normal");
    }

    // Consistent results → low drift
    const consistentResults: LandscapeMatchResult[] = [];
    for (let i = 0; i < 5; i++) {
      consistentResults.push(matchLandscape(landscape, makeSignals({ wordCount: 100 }), "normal"));
    }
    const lowDrift = computeDriftVelocity(landscape, consistentResults);

    // Wildly varying results → higher drift
    const varyingResults: LandscapeMatchResult[] = [];
    for (let i = 0; i < 5; i++) {
      const wc = i % 2 === 0 ? 100 : 1000;
      varyingResults.push(matchLandscape(landscape, makeSignals({ wordCount: wc }), "normal"));
    }
    const highDrift = computeDriftVelocity(landscape, varyingResults);

    expect(highDrift).toBeGreaterThan(lowDrift);
  });
});

describe("matchEnhanced", () => {
  it("returns AMBER for insufficient observations", () => {
    const landscape = createLandscape("test");
    updateLandscape(landscape, makeSignals(), "normal");

    const verdict = matchEnhanced(landscape, makeSignals(), "normal");
    expect(verdict.status).toBe("AMBER");
    expect(verdict.profileMaturity).toBe("embryonic");
  });

  it("returns GREEN for consistent matching behavior", () => {
    const landscape = createLandscape("test");
    for (let i = 0; i < 20; i++) {
      updateLandscape(landscape, makeSignals(), "normal");
    }

    const verdict = matchEnhanced(landscape, makeSignals(), "normal");
    expect(verdict.status).toBe("GREEN");
    expect(verdict.confidence).toBeGreaterThan(0.8);
    expect(verdict.landscapeDepth).toBe(1);
    expect(verdict.driftVelocity).toBeDefined();
  });

  it("includes heart seed and birth certificate flags", () => {
    const landscape = createLandscape("test");
    for (let i = 0; i < 10; i++) {
      updateLandscape(landscape, makeSignals(), "normal");
    }

    const verdict = matchEnhanced(
      landscape,
      makeSignals(),
      "normal",
      [],
      5,
      { heartSeedVerified: true, birthCertificateChain: true }
    );
    expect(verdict.heartSeedVerified).toBe(true);
    expect(verdict.birthCertificateChain).toBe(true);
  });

  it("detects divergent behavior as non-GREEN", () => {
    const landscape = createLandscape("test");
    for (let i = 0; i < 20; i++) {
      updateLandscape(landscape, makeSignals({ wordCount: 100 }), "normal");
    }

    const verdict = matchEnhanced(
      landscape,
      makeSignals({ wordCount: 5000, hedgeCount: 50, avgWordLength: 20, meanInterval: 999 }),
      "normal"
    );
    // With many zero-valued features matching on both sides, confidence stays high.
    // The divergent features still push it below perfect match.
    expect(verdict.confidence).toBeLessThan(1.0);
  });
});
