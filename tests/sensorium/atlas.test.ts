import { describe, it, expect } from "vitest";
import {
  PhenotypeAtlas,
  DEFAULT_SENSE_WEIGHTS,
  type SenseFeatures,
  type ReferenceProfile,
} from "../../src/sensorium/atlas.js";

describe("PhenotypeAtlas", () => {
  function claudeFeatures(variation: number = 0): SenseFeatures {
    return {
      temporal: {
        temporal_mean_interval: 12.4 + variation * 0.2,
        temporal_burstiness: 3.2 + variation * 0.1,
        temporal_time_to_first_token: 450 + variation * 5,
      },
      topology: {
        topology_paragraph_count: 4 + (variation % 2),
        topology_list_ratio: 0.2 + variation * 0.01,
      },
      vocabulary: {
        vocab_type_token_ratio: 0.72 + variation * 0.005,
        vocab_contraction_ratio: 0.03 + variation * 0.001,
      },
    };
  }

  function gptFeatures(variation: number = 0): SenseFeatures {
    return {
      temporal: {
        temporal_mean_interval: 6.4 + variation * 0.15,
        temporal_burstiness: 1.8 + variation * 0.08,
        temporal_time_to_first_token: 200 + variation * 3,
      },
      topology: {
        topology_paragraph_count: 2 + (variation % 2),
        topology_list_ratio: 0.35 + variation * 0.01,
      },
      vocabulary: {
        vocab_type_token_ratio: 0.58 + variation * 0.004,
        vocab_contraction_ratio: 0.005 + variation * 0.001,
      },
    };
  }

  describe("profile management", () => {
    it("starts empty", () => {
      const atlas = new PhenotypeAtlas();
      expect(atlas.size).toBe(0);
    });

    it("adds profiles via updateProfile", () => {
      const atlas = new PhenotypeAtlas();
      atlas.updateProfile("claude-hash", "claude", claudeFeatures());
      expect(atlas.size).toBe(1);
      expect(atlas.getProfile("claude-hash")).toBeDefined();
    });

    it("accumulates observations with Welford's algorithm", () => {
      const atlas = new PhenotypeAtlas();
      for (let i = 0; i < 10; i++) {
        atlas.updateProfile("claude-hash", "claude", claudeFeatures(i));
      }
      const profile = atlas.getProfile("claude-hash")!;
      expect(profile.observationCount).toBe(10);
      expect(profile.temporal["temporal_mean_interval"].count).toBe(10);
    });
  });

  describe("classifyObservation()", () => {
    it("returns match=false when atlas is empty", () => {
      const atlas = new PhenotypeAtlas();
      const result = atlas.classifyObservation(claudeFeatures(), "some-hash");
      expect(result.match).toBe(false);
      expect(result.distance).toBe(Infinity);
    });

    it("correctly classifies Claude observation against Claude reference", () => {
      const atlas = new PhenotypeAtlas();
      for (let i = 0; i < 20; i++) {
        atlas.updateProfile("claude-hash", "claude", claudeFeatures(i));
        atlas.updateProfile("gpt-hash", "gpt", gptFeatures(i));
      }

      const result = atlas.classifyObservation(claudeFeatures(3), "claude-hash");
      expect(result.match).toBe(true);
      expect(result.nearestGenome).toBe("claude-hash");
      expect(result.nearestLabel).toBe("claude");
    });

    it("detects when GPT observation claims to be Claude", () => {
      const atlas = new PhenotypeAtlas();
      for (let i = 0; i < 20; i++) {
        atlas.updateProfile("claude-hash", "claude", claudeFeatures(i));
        atlas.updateProfile("gpt-hash", "gpt", gptFeatures(i));
      }

      // GPT features claiming to be Claude
      const result = atlas.classifyObservation(gptFeatures(2), "claude-hash");
      expect(result.match).toBe(false);
      expect(result.nearestGenome).toBe("gpt-hash");
      expect(result.declaredGenome).toBe("claude-hash");
    });

    it("margin is positive when classification is confident", () => {
      const atlas = new PhenotypeAtlas();
      for (let i = 0; i < 30; i++) {
        atlas.updateProfile("claude-hash", "claude", claudeFeatures(i));
        atlas.updateProfile("gpt-hash", "gpt", gptFeatures(i));
      }

      const result = atlas.classifyObservation(claudeFeatures(5), "claude-hash");
      expect(result.margin).toBeGreaterThan(0);
    });

    it("uses sense weights for classification", () => {
      // With default weights (temporal: 5, topology: 2, vocabulary: 1),
      // temporal features should dominate the distance calculation
      const atlas = new PhenotypeAtlas();
      for (let i = 0; i < 20; i++) {
        atlas.updateProfile("a-hash", "model-a", {
          temporal: { temporal_mean_interval: 10 + i * 0.1 },
          topology: { topology_paragraph_count: 4 },
          vocabulary: { vocab_type_token_ratio: 0.7 },
        });
        atlas.updateProfile("b-hash", "model-b", {
          temporal: { temporal_mean_interval: 50 + i * 0.1 },
          topology: { topology_paragraph_count: 4 },
          vocabulary: { vocab_type_token_ratio: 0.7 },
        });
      }

      // Observation with temporal closer to model-a
      const result = atlas.classifyObservation({
        temporal: { temporal_mean_interval: 12 },
        topology: { topology_paragraph_count: 4 },
        vocabulary: { vocab_type_token_ratio: 0.7 },
      }, "a-hash");

      expect(result.nearestGenome).toBe("a-hash");
    });
  });

  describe("serialization", () => {
    it("round-trips through JSON", () => {
      const atlas = new PhenotypeAtlas();
      for (let i = 0; i < 10; i++) {
        atlas.updateProfile("hash-a", "model-a", claudeFeatures(i));
        atlas.updateProfile("hash-b", "model-b", gptFeatures(i));
      }

      const json = atlas.toJSON();
      const restored = PhenotypeAtlas.fromJSON(json);

      expect(restored.size).toBe(2);
      expect(restored.getProfile("hash-a")!.observationCount).toBe(10);
      expect(restored.getProfile("hash-b")!.observationCount).toBe(10);

      // Classification should work the same
      const original = atlas.classifyObservation(claudeFeatures(3), "hash-a");
      const restoredResult = restored.classifyObservation(claudeFeatures(3), "hash-a");
      expect(restoredResult.nearestGenome).toBe(original.nearestGenome);
    });
  });
});
