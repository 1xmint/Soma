import { describe, it, expect } from "vitest";
import nacl from "tweetnacl";
import { encodeBase64, decodeBase64 } from "tweetnacl-util";
import {
  createGenome,
  computeHash,
  commitGenome,
  verifyCommitment,
  mutateGenome,
  sha256,
  publicKeyToDid,
} from "../src/core/genome.js";
import {
  generateEphemeralKeyPair,
  createHandshakePayload,
  establishChannel,
} from "../src/core/channel.js";

// --- Genome Tests ---

describe("Genome", () => {
  const baseConfig = {
    modelProvider: "meta",
    modelId: "llama-3.3-70b",
    modelVersion: "2025-01",
    systemPrompt: "You are a helpful assistant.",
    toolManifest: JSON.stringify({ tools: ["search", "calculate"] }),
    runtimeId: "node-22-linux-x64",
  };

  it("creates a genome with hashed secrets", () => {
    const genome = createGenome(baseConfig);

    expect(genome.modelProvider).toBe("meta");
    expect(genome.modelId).toBe("llama-3.3-70b");
    expect(genome.version).toBe(1);
    expect(genome.parentHash).toBeNull();

    // System prompt and tool manifest should be hashed, not plaintext
    expect(genome.systemPromptHash).toBe(sha256(baseConfig.systemPrompt));
    expect(genome.toolManifestHash).toBe(sha256(baseConfig.toolManifest));
    expect(genome.systemPromptHash).not.toBe(baseConfig.systemPrompt);
  });

  it("produces deterministic hashes for the same genome", () => {
    const genome = createGenome(baseConfig);
    const hash1 = computeHash(genome);
    const hash2 = computeHash(genome);

    expect(hash1).toBe(hash2);
    expect(hash1).toHaveLength(64); // SHA-256 hex
  });

  it("produces different hashes for different genomes", () => {
    const genome1 = createGenome(baseConfig);
    const genome2 = createGenome({ ...baseConfig, modelId: "llama-3.1-8b" });

    expect(computeHash(genome1)).not.toBe(computeHash(genome2));
  });

  it("detects epigenetic variants — same model, different system prompt", () => {
    const genome1 = createGenome(baseConfig);
    const genome2 = createGenome({
      ...baseConfig,
      systemPrompt: "You are a formal academic assistant.",
    });

    // Same model, different system prompt hash → different genome hash
    expect(genome1.modelId).toBe(genome2.modelId);
    expect(genome1.systemPromptHash).not.toBe(genome2.systemPromptHash);
    expect(computeHash(genome1)).not.toBe(computeHash(genome2));
  });
});

describe("Genome Commitment", () => {
  const keyPair = nacl.sign.keyPair();
  const genome = createGenome({
    modelProvider: "meta",
    modelId: "llama-3.3-70b",
    modelVersion: "2025-01",
    systemPrompt: "You are a helpful assistant.",
    toolManifest: "{}",
    runtimeId: "node-22-linux-x64",
  });

  it("creates a valid commitment with signature and DID", () => {
    const commitment = commitGenome(genome, keyPair);

    expect(commitment.hash).toHaveLength(64);
    expect(commitment.signature).toBeTruthy();
    expect(commitment.publicKey).toBeTruthy();
    expect(commitment.did).toMatch(/^did:key:z/);
  });

  it("verifies a valid commitment", () => {
    const commitment = commitGenome(genome, keyPair);
    expect(verifyCommitment(commitment)).toBe(true);
  });

  it("rejects a commitment with tampered genome", () => {
    const commitment = commitGenome(genome, keyPair);
    const tampered = {
      ...commitment,
      genome: { ...commitment.genome, modelId: "gpt-4o" },
    };
    expect(verifyCommitment(tampered)).toBe(false);
  });

  it("rejects a commitment with tampered hash", () => {
    const commitment = commitGenome(genome, keyPair);
    const tampered = { ...commitment, hash: "0".repeat(64) };
    expect(verifyCommitment(tampered)).toBe(false);
  });

  it("rejects a commitment with wrong signing key", () => {
    const commitment = commitGenome(genome, keyPair);
    const otherKeyPair = nacl.sign.keyPair();
    const tampered = {
      ...commitment,
      // Swap in a different public key — signature won't match
      publicKey: Buffer.from(otherKeyPair.publicKey).toString("base64"),
      did: publicKeyToDid(otherKeyPair.publicKey),
    };
    expect(verifyCommitment(tampered)).toBe(false);
  });

  it("rejects a commitment with mismatched DID", () => {
    const commitment = commitGenome(genome, keyPair);
    const tampered = { ...commitment, did: "did:key:zFAKE" };
    expect(verifyCommitment(tampered)).toBe(false);
  });
});

describe("Genome Mutation", () => {
  it("creates a versioned mutation linked to parent", () => {
    const parent = createGenome({
      modelProvider: "meta",
      modelId: "llama-3.3-70b",
      modelVersion: "2025-01",
      systemPrompt: "v1",
      toolManifest: "{}",
      runtimeId: "node-22-linux-x64",
    });
    const parentHash = computeHash(parent);

    const mutated = mutateGenome(parent, parentHash, {
      modelVersion: "2025-03",
    });

    expect(mutated.version).toBe(2);
    expect(mutated.parentHash).toBe(parentHash);
    expect(mutated.modelVersion).toBe("2025-03");
    // Unchanged fields preserved
    expect(mutated.modelId).toBe("llama-3.3-70b");
  });

  it("mutation produces a different hash than parent", () => {
    const parent = createGenome({
      modelProvider: "meta",
      modelId: "llama-3.3-70b",
      modelVersion: "2025-01",
      systemPrompt: "v1",
      toolManifest: "{}",
      runtimeId: "node-22-linux-x64",
    });
    const parentHash = computeHash(parent);
    const mutated = mutateGenome(parent, parentHash, {
      modelVersion: "2025-03",
    });

    expect(computeHash(mutated)).not.toBe(parentHash);
  });
});

// --- Channel Tests ---

describe("Authenticated Encrypted Channel", () => {
  // Helper: create an agent with signing keys, genome, and commitment
  function createAgent(modelId: string, systemPrompt: string) {
    const signingKeyPair = nacl.sign.keyPair();
    const genome = createGenome({
      modelProvider: "test",
      modelId,
      modelVersion: "1.0",
      systemPrompt,
      toolManifest: "{}",
      runtimeId: "test-runtime",
    });
    const commitment = commitGenome(genome, signingKeyPair);
    return { signingKeyPair, genome, commitment };
  }

  it("establishes a channel between two agents", () => {
    const agentA = createAgent("model-a", "prompt-a");
    const agentB = createAgent("model-b", "prompt-b");

    const ephA = generateEphemeralKeyPair();
    const ephB = generateEphemeralKeyPair();

    const handshakeA = createHandshakePayload(agentA.commitment, ephA);
    const handshakeB = createHandshakePayload(agentB.commitment, ephB);

    const channelA = establishChannel(
      { handshake: handshakeA, ephemeralKeyPair: ephA },
      handshakeB
    );
    const channelB = establishChannel(
      { handshake: handshakeB, ephemeralKeyPair: ephB },
      handshakeA
    );

    expect(channelA.localDid).toBe(agentA.commitment.did);
    expect(channelA.remoteDid).toBe(agentB.commitment.did);
    expect(channelB.localDid).toBe(agentB.commitment.did);
    expect(channelB.remoteDid).toBe(agentA.commitment.did);
  });

  it("encrypts and decrypts messages bidirectionally", () => {
    const agentA = createAgent("model-a", "prompt-a");
    const agentB = createAgent("model-b", "prompt-b");

    const ephA = generateEphemeralKeyPair();
    const ephB = generateEphemeralKeyPair();

    const handshakeA = createHandshakePayload(agentA.commitment, ephA);
    const handshakeB = createHandshakePayload(agentB.commitment, ephB);

    const channelA = establishChannel(
      { handshake: handshakeA, ephemeralKeyPair: ephA },
      handshakeB
    );
    const channelB = establishChannel(
      { handshake: handshakeB, ephemeralKeyPair: ephB },
      handshakeA
    );

    // A → B
    const encrypted = channelA.encrypt("Hello from Agent A");
    const decrypted = channelB.decrypt(encrypted);
    expect(decrypted).toBe("Hello from Agent A");

    // B → A
    const encrypted2 = channelB.encrypt("Hello from Agent B");
    const decrypted2 = channelA.decrypt(encrypted2);
    expect(decrypted2).toBe("Hello from Agent B");
  });

  it("produces different ciphertext for the same plaintext (random nonce)", () => {
    const agentA = createAgent("model-a", "prompt-a");
    const agentB = createAgent("model-b", "prompt-b");

    const ephA = generateEphemeralKeyPair();
    const ephB = generateEphemeralKeyPair();

    const channelA = establishChannel(
      {
        handshake: createHandshakePayload(agentA.commitment, ephA),
        ephemeralKeyPair: ephA,
      },
      createHandshakePayload(agentB.commitment, ephB)
    );

    const msg1 = channelA.encrypt("same message");
    const msg2 = channelA.encrypt("same message");

    // Different nonces → different ciphertexts
    expect(msg1.nonce).not.toBe(msg2.nonce);
    expect(msg1.ciphertext).not.toBe(msg2.ciphertext);
  });

  it("rejects tampered ciphertext", () => {
    const agentA = createAgent("model-a", "prompt-a");
    const agentB = createAgent("model-b", "prompt-b");

    const ephA = generateEphemeralKeyPair();
    const ephB = generateEphemeralKeyPair();

    const channelA = establishChannel(
      {
        handshake: createHandshakePayload(agentA.commitment, ephA),
        ephemeralKeyPair: ephA,
      },
      createHandshakePayload(agentB.commitment, ephB)
    );
    const channelB = establishChannel(
      {
        handshake: createHandshakePayload(agentB.commitment, ephB),
        ephemeralKeyPair: ephB,
      },
      createHandshakePayload(agentA.commitment, ephA)
    );

    const encrypted = channelA.encrypt("secret message");
    // Tamper with ciphertext by flipping bits in the decoded bytes
    const ciphertextBytes = decodeBase64(encrypted.ciphertext);
    ciphertextBytes[0] ^= 0xff;
    ciphertextBytes[1] ^= 0xff;
    const tampered = { ...encrypted, ciphertext: encodeBase64(ciphertextBytes) };

    expect(() => channelB.decrypt(tampered)).toThrow("Decryption failed");
  });

  it("third party cannot decrypt without session key", () => {
    const agentA = createAgent("model-a", "prompt-a");
    const agentB = createAgent("model-b", "prompt-b");
    const eavesdropper = createAgent("model-evil", "evil-prompt");

    const ephA = generateEphemeralKeyPair();
    const ephB = generateEphemeralKeyPair();
    const ephEvil = generateEphemeralKeyPair();

    const channelA = establishChannel(
      {
        handshake: createHandshakePayload(agentA.commitment, ephA),
        ephemeralKeyPair: ephA,
      },
      createHandshakePayload(agentB.commitment, ephB)
    );

    // Eavesdropper establishes their own channel with A — gets a DIFFERENT session key
    const channelEvil = establishChannel(
      {
        handshake: createHandshakePayload(eavesdropper.commitment, ephEvil),
        ephemeralKeyPair: ephEvil,
      },
      createHandshakePayload(agentA.commitment, ephA)
    );

    const encrypted = channelA.encrypt("secret between A and B");

    // Eavesdropper can't decrypt A↔B traffic
    expect(() => channelEvil.decrypt(encrypted)).toThrow("Decryption failed");
  });

  it("rejects channel with invalid genome commitment", () => {
    const agentA = createAgent("model-a", "prompt-a");
    const agentB = createAgent("model-b", "prompt-b");

    const ephA = generateEphemeralKeyPair();
    const ephB = generateEphemeralKeyPair();

    const handshakeA = createHandshakePayload(agentA.commitment, ephA);
    const handshakeB = createHandshakePayload(agentB.commitment, ephB);

    // Tamper with B's genome in its handshake
    const tamperedHandshake = {
      ...handshakeB,
      genomeCommitment: {
        ...handshakeB.genomeCommitment,
        genome: {
          ...handshakeB.genomeCommitment.genome,
          modelId: "fake-model",
        },
      },
    };

    expect(() =>
      establishChannel(
        { handshake: handshakeA, ephemeralKeyPair: ephA },
        tamperedHandshake
      )
    ).toThrow("Remote genome commitment verification failed");
  });
});
