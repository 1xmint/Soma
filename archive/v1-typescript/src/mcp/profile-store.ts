/**
 * Local file-based storage for phenotypic profiles.
 *
 * Each genome gets a JSON file containing its accumulated behavioral
 * statistics. Like immunological memory — the system remembers what
 * "self" looks like for each genome it has encountered.
 *
 * No database. No central server. JSON files on your machine.
 */

import { readFile, writeFile, mkdir } from "node:fs/promises";
import { existsSync } from "node:fs";
import { join } from "node:path";
import { createProfile, type PhenotypicProfile } from "../sensorium/matcher.js";

const DEFAULT_STORE_PATH = ".soma/profiles";

export class ProfileStore {
  private readonly basePath: string;
  private cache: Map<string, PhenotypicProfile> = new Map();

  constructor(basePath?: string) {
    this.basePath = basePath ?? DEFAULT_STORE_PATH;
  }

  /** Ensure the storage directory exists. */
  async init(): Promise<void> {
    if (!existsSync(this.basePath)) {
      await mkdir(this.basePath, { recursive: true });
    }
  }

  /** Load or create a profile for a genome hash. */
  async load(genomeHash: string): Promise<PhenotypicProfile> {
    // Check in-memory cache first
    const cached = this.cache.get(genomeHash);
    if (cached) return cached;

    const filePath = this.profilePath(genomeHash);
    if (existsSync(filePath)) {
      const raw = await readFile(filePath, "utf-8");
      const profile = JSON.parse(raw) as PhenotypicProfile;
      this.cache.set(genomeHash, profile);
      return profile;
    }

    // New genome — create empty profile (immune system starts learning)
    const profile = createProfile(genomeHash);
    this.cache.set(genomeHash, profile);
    return profile;
  }

  /** Persist a profile to disk. */
  async save(profile: PhenotypicProfile): Promise<void> {
    await this.init();
    this.cache.set(profile.genomeHash, profile);
    const filePath = this.profilePath(profile.genomeHash);
    await writeFile(filePath, JSON.stringify(profile, null, 2));
  }

  private profilePath(genomeHash: string): string {
    // Sanitize hash for filesystem safety
    const safe = genomeHash.replace(/[^a-zA-Z0-9]/g, "");
    return join(this.basePath, `${safe}.json`);
  }
}
