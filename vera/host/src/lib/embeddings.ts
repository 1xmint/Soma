import { createHash } from 'node:crypto';

/**
 * Generate a deterministic 1536-dimensional unit vector from any text string.
 *
 * Algorithm:
 * 1. Iteratively SHA-256 hash the seed (starting with the input text).
 * 2. Extract signed 32-bit integers from each hash digest, scaled to [-1, 1].
 * 3. Chain: next seed = current hash hex string.
 * 4. Normalize the collected values to a unit vector.
 *
 * This produces a stable embedding suitable for cosine similarity comparisons.
 * It is NOT semantically meaningful — Week 3 will replace this with a real provider.
 */
export function stubEmbed(text: string): number[] {
  const TARGET = 1536;
  const values: number[] = [];
  let seed = text;

  while (values.length < TARGET) {
    const hashBuf = createHash('sha256').update(seed).digest();
    // Read signed 32-bit integers: each 4-byte chunk yields one float in [-1, 1]
    let offset = 0;
    while (offset + 4 <= hashBuf.length && values.length < TARGET) {
      const int32 = hashBuf.readInt32BE(offset);
      // Scale: Int32 range is [-2^31, 2^31-1], divide by 2^31 to get [-1, 1]
      values.push(int32 / 2147483648);
      offset += 4;
    }
    // Chain: use the hex of the current hash as the next seed
    seed = hashBuf.toString('hex');
  }

  // Normalize to unit vector (required for cosine similarity correctness)
  let magnitude = 0;
  for (const v of values) {
    magnitude += v * v;
  }
  magnitude = Math.sqrt(magnitude);

  if (magnitude === 0) {
    // Degenerate case: return a unit vector along the first dimension
    const unit = new Array<number>(TARGET).fill(0);
    unit[0] = 1;
    return unit;
  }

  return values.map((v) => v / magnitude);
}
