import { describe, it, expect } from "vitest";
import { getCryptoProvider } from "../../src/core/crypto-provider.js";
import { CredentialVault } from "../../src/heart/credential-vault.js";

const crypto = getCryptoProvider();

describe("CredentialVault", () => {
  function createVault(): CredentialVault {
    const keyPair = crypto.signing.generateKeyPair();
    return new CredentialVault(keyPair.secretKey);
  }

  it("stores and retrieves a credential", () => {
    const vault = createVault();
    vault.store("api_key", "sk-test-12345");
    expect(vault.retrieve("api_key")).toBe("sk-test-12345");
  });

  it("encrypts credentials at rest — different nonces produce different ciphertext", () => {
    const vault = createVault();
    vault.store("key1", "same-value");
    vault.store("key2", "same-value");
    // Both store the same value but are independently encrypted
    expect(vault.retrieve("key1")).toBe("same-value");
    expect(vault.retrieve("key2")).toBe("same-value");
  });

  it("throws on retrieving non-existent credential", () => {
    const vault = createVault();
    expect(() => vault.retrieve("missing")).toThrow("Credential not found: missing");
  });

  it("reports existence with has()", () => {
    const vault = createVault();
    expect(vault.has("key")).toBe(false);
    vault.store("key", "value");
    expect(vault.has("key")).toBe(true);
  });

  it("lists credential names without exposing values", () => {
    const vault = createVault();
    vault.store("api_key", "secret1");
    vault.store("db_key", "secret2");
    vault.store("tool:search", "secret3");
    expect(vault.names()).toEqual(["api_key", "db_key", "tool:search"]);
  });

  it("handles special characters in credential values", () => {
    const vault = createVault();
    const special = "p@$$w0rd!#%^&*()_+-={}[]|\\:\";<>?,./~`";
    vault.store("special", special);
    expect(vault.retrieve("special")).toBe(special);
  });

  it("handles empty string credentials", () => {
    const vault = createVault();
    vault.store("empty", "");
    expect(vault.retrieve("empty")).toBe("");
  });

  it("handles long credential values", () => {
    const vault = createVault();
    const longValue = "x".repeat(10000);
    vault.store("long", longValue);
    expect(vault.retrieve("long")).toBe(longValue);
  });

  it("overwrites existing credentials on re-store", () => {
    const vault = createVault();
    vault.store("key", "old-value");
    vault.store("key", "new-value");
    expect(vault.retrieve("key")).toBe("new-value");
  });

  it("destroy() wipes all credentials", () => {
    const vault = createVault();
    vault.store("key", "secret");
    vault.destroy();
    expect(vault.has("key")).toBe(false);
    expect(vault.names()).toEqual([]);
  });

  it("different signing keys produce independent vaults", () => {
    const key1 = crypto.signing.generateKeyPair();
    const key2 = crypto.signing.generateKeyPair();
    const vault1 = new CredentialVault(key1.secretKey);
    const vault2 = new CredentialVault(key2.secretKey);

    vault1.store("key", "value-for-vault1");
    vault2.store("key", "value-for-vault2");

    expect(vault1.retrieve("key")).toBe("value-for-vault1");
    expect(vault2.retrieve("key")).toBe("value-for-vault2");
  });
});
