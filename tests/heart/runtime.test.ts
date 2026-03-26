import { describe, it, expect, vi, beforeEach } from "vitest";
import nacl from "tweetnacl";
import {
  HeartRuntime,
  createSomaHeart,
  type HeartConfig,
  type HeartbeatToken,
} from "../../src/heart/runtime.js";
import {
  createGenome,
  commitGenome,
  type GenomeCommitment,
} from "../../src/core/genome.js";
import {
  generateEphemeralKeyPair,
  createHandshakePayload,
} from "../../src/core/channel.js";
import { HeartbeatChain } from "../../src/heart/heartbeat.js";
import { verifyBirthCertificate } from "../../src/heart/birth-certificate.js";

// --- Test helpers ---

function makeGenomeCommitment(keyPair: nacl.SignKeyPair): GenomeCommitment {
  const genome = createGenome({
    modelProvider: "test",
    modelId: "test-model",
    modelVersion: "1.0",
    systemPrompt: "You are a test agent.",
    toolManifest: "{}",
    runtimeId: "test-runtime",
  });
  return commitGenome(genome, keyPair);
}

function makeHeartConfig(overrides?: Partial<HeartConfig>): HeartConfig {
  const keyPair = nacl.sign.keyPair();
  const genome = makeGenomeCommitment(keyPair);
  return {
    genome,
    signingKeyPair: keyPair,
    modelApiKey: "sk-test-key-12345",
    modelBaseUrl: "https://api.test.com/v1",
    modelId: "test-model-1",
    toolCredentials: { database: "db-secret-key", search: "search-api-key" },
    dataSources: [
      {
        name: "market-api",
        url: "https://market.test.com/api",
        headers: { Authorization: "Bearer market-token", "Content-Type": "application/json" },
      },
    ],
    ...overrides,
  };
}

describe("HeartRuntime", () => {
  describe("construction", () => {
    it("creates a heart with factory function", () => {
      const heart = createSomaHeart(makeHeartConfig());
      expect(heart).toBeInstanceOf(HeartRuntime);
      expect(heart.isAlive).toBe(true);
    });

    it("has the correct DID", () => {
      const config = makeHeartConfig();
      const heart = new HeartRuntime(config);
      expect(heart.did).toBe(config.genome.did);
    });

    it("exposes the genome commitment", () => {
      const config = makeHeartConfig();
      const heart = new HeartRuntime(config);
      expect(heart.genomeCommitment).toEqual(config.genome);
    });

    it("starts with an empty heartbeat chain", () => {
      const heart = createSomaHeart(makeHeartConfig());
      expect(heart.heartbeats.length).toBe(0);
    });
  });

  describe("session management", () => {
    it("creates a session with a remote party", () => {
      const heart = createSomaHeart(makeHeartConfig());
      const remoteKeyPair = nacl.sign.keyPair();
      const remoteGenome = makeGenomeCommitment(remoteKeyPair);

      const session = heart.createSession(remoteGenome.did, remoteGenome);
      expect(session.sessionId).toBeTruthy();
      expect(session.remoteDid).toBe(remoteGenome.did);
      expect(session.remoteGenome).toEqual(remoteGenome);
      expect(session.channel).toBeNull();
      expect(session.interactionCounter).toBe(0);
      expect(session.heartbeatChain.length).toBe(1); // session_start
    });

    it("retrieves a session by ID", () => {
      const heart = createSomaHeart(makeHeartConfig());
      const remoteKeyPair = nacl.sign.keyPair();
      const remoteGenome = makeGenomeCommitment(remoteKeyPair);

      const session = heart.createSession(remoteGenome.did, remoteGenome);
      const retrieved = heart.getSession(session.sessionId);
      expect(retrieved).toBe(session);
    });

    it("returns undefined for unknown session", () => {
      const heart = createSomaHeart(makeHeartConfig());
      expect(heart.getSession("nonexistent")).toBeUndefined();
    });

    it("completes handshake and establishes encrypted channel", () => {
      const config = makeHeartConfig();
      const heart = new HeartRuntime(config);

      const remoteKeyPair = nacl.sign.keyPair();
      const remoteGenome = makeGenomeCommitment(remoteKeyPair);

      const session = heart.createSession(remoteGenome.did, remoteGenome);

      // Get local handshake payload
      const localHandshake = heart.getHandshakePayload(session.sessionId);

      // Create remote's ephemeral key and handshake
      const remoteEphemeral = generateEphemeralKeyPair();
      const remoteHandshake = createHandshakePayload(remoteGenome, remoteEphemeral);

      // Complete handshake
      heart.completeHandshake(session.sessionId, remoteHandshake);

      expect(session.channel).not.toBeNull();
      expect(session.sessionKey).not.toBeNull();
      expect(session.sessionKey!.length).toBe(32);
    });

    it("established channel can encrypt and decrypt", () => {
      const config = makeHeartConfig();
      const heart = new HeartRuntime(config);

      const remoteKeyPair = nacl.sign.keyPair();
      const remoteGenome = makeGenomeCommitment(remoteKeyPair);

      const session = heart.createSession(remoteGenome.did, remoteGenome);

      const remoteEphemeral = generateEphemeralKeyPair();
      const remoteHandshake = createHandshakePayload(remoteGenome, remoteEphemeral);

      heart.completeHandshake(session.sessionId, remoteHandshake);

      const encrypted = session.channel!.encrypt("test message");
      expect(encrypted.ciphertext).toBeTruthy();
      expect(encrypted.nonce).toBeTruthy();
    });
  });

  describe("callTool()", () => {
    it("executes a tool and returns heartbeats + birth certificate", async () => {
      const config = makeHeartConfig();
      const heart = new HeartRuntime(config);

      const mockExecutor = vi.fn(async (credential: string, args: Record<string, unknown>) => {
        expect(credential).toBe("db-secret-key");
        return { rows: [{ id: 1, name: "test" }] };
      });

      const result = await heart.callTool("database", { query: "SELECT * FROM users" }, mockExecutor);

      expect(mockExecutor).toHaveBeenCalledOnce();
      expect(result.result).toEqual({ rows: [{ id: 1, name: "test" }] });
      expect(result.heartbeats.length).toBe(3); // tool_call, tool_result, birth_certificate
      expect(result.heartbeats[0].eventType).toBe("tool_call");
      expect(result.heartbeats[1].eventType).toBe("tool_result");
      expect(result.heartbeats[2].eventType).toBe("birth_certificate");
      expect(result.birthCertificate.dataHash).toBeTruthy();
      expect(result.birthCertificate.source.type).toBe("api");
    });

    it("provides empty string for unknown tool credential", async () => {
      const config = makeHeartConfig();
      const heart = new HeartRuntime(config);

      const mockExecutor = vi.fn(async (credential: string) => {
        expect(credential).toBe("");
        return "ok";
      });

      await heart.callTool("unknown-tool", {}, mockExecutor);
      expect(mockExecutor).toHaveBeenCalledOnce();
    });

    it("birth certificate is verifiable", async () => {
      const config = makeHeartConfig();
      const heart = new HeartRuntime(config);

      const result = await heart.callTool(
        "search",
        { q: "test" },
        async () => "search results"
      );

      expect(
        verifyBirthCertificate(result.birthCertificate, config.signingKeyPair.publicKey)
      ).toBe(true);
    });

    it("logs tool calls in the heartbeat chain", async () => {
      const config = makeHeartConfig();
      const heart = new HeartRuntime(config);

      await heart.callTool("database", { q: "1" }, async () => "r1");
      await heart.callTool("search", { q: "2" }, async () => "r2");

      // 3 heartbeats per tool call = 6 total
      expect(heart.heartbeats.length).toBe(6);
      expect(HeartbeatChain.verify([...heart.heartbeats.getChain()])).toBe(true);
    });
  });

  describe("fetchData()", () => {
    it("fetches data through the heart with custom fetcher", async () => {
      const config = makeHeartConfig();
      const heart = new HeartRuntime(config);

      const mockFetcher = vi.fn(
        async (url: string, headers: Record<string, string>, query: string) => {
          expect(url).toBe("https://market.test.com/api");
          expect(headers.Authorization).toBe("Bearer market-token");
          expect(headers["Content-Type"]).toBe("application/json");
          return '{"price": 100}';
        }
      );

      const result = await heart.fetchData("market-api", "AAPL", mockFetcher);

      expect(mockFetcher).toHaveBeenCalledOnce();
      expect(result.content).toBe('{"price": 100}');
      expect(result.heartbeats.length).toBe(3); // data_fetch, data_received, birth_certificate
      expect(result.heartbeats[0].eventType).toBe("data_fetch");
      expect(result.heartbeats[1].eventType).toBe("data_received");
      expect(result.heartbeats[2].eventType).toBe("birth_certificate");
    });

    it("throws for unknown data source", async () => {
      const heart = createSomaHeart(makeHeartConfig());
      await expect(heart.fetchData("nonexistent", "q")).rejects.toThrow(
        "Unknown data source: nonexistent"
      );
    });

    it("birth certificate is verifiable", async () => {
      const config = makeHeartConfig();
      const heart = new HeartRuntime(config);

      const result = await heart.fetchData(
        "market-api",
        "query",
        async () => "response data"
      );

      expect(
        verifyBirthCertificate(result.birthCertificate, config.signingKeyPair.publicKey)
      ).toBe(true);
    });
  });

  describe("destroy()", () => {
    it("kills the heart — no further computation possible", () => {
      const heart = createSomaHeart(makeHeartConfig());
      expect(heart.isAlive).toBe(true);

      heart.destroy();
      expect(heart.isAlive).toBe(false);
    });

    it("generate() throws after destroy", async () => {
      const heart = createSomaHeart(makeHeartConfig());
      heart.destroy();

      const gen = heart.generate({
        messages: [{ role: "user", content: "test" }],
      });
      await expect(gen.next()).rejects.toThrow("Heart has been destroyed");
    });

    it("callTool() throws after destroy", async () => {
      const heart = createSomaHeart(makeHeartConfig());
      heart.destroy();

      await expect(
        heart.callTool("database", {}, async () => "")
      ).rejects.toThrow("Heart has been destroyed");
    });

    it("fetchData() throws after destroy", async () => {
      const heart = createSomaHeart(makeHeartConfig());
      heart.destroy();

      await expect(
        heart.fetchData("market-api", "q", async () => "")
      ).rejects.toThrow("Heart has been destroyed");
    });

    it("createSession() throws after destroy", () => {
      const heart = createSomaHeart(makeHeartConfig());
      const remoteKeyPair = nacl.sign.keyPair();
      const remoteGenome = makeGenomeCommitment(remoteKeyPair);

      heart.destroy();
      expect(() => heart.createSession(remoteGenome.did, remoteGenome)).toThrow(
        "Heart has been destroyed"
      );
    });
  });

  describe("heartbeat chain integrity", () => {
    it("maintains valid chain across mixed operations", async () => {
      const config = makeHeartConfig();
      const heart = new HeartRuntime(config);

      await heart.callTool("database", { q: "test" }, async () => "r");
      await heart.fetchData("market-api", "q", async () => "data");
      await heart.callTool("search", { q: "find" }, async () => "found");

      const chain = [...heart.heartbeats.getChain()];
      expect(chain.length).toBe(9); // 3 per operation * 3 operations
      expect(HeartbeatChain.verify(chain)).toBe(true);
    });
  });
});
