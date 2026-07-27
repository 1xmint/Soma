const TRANSIENT = ["EACCES", "EBUSY", "EPERM"];

// Windows returns EPERM/EACCES/EBUSY when another handle, a pending delete, or a
// background scanner holds a path. Those are contention, not a denial of
// authority, and they resolve on their own. host-lock.mjs already retried them
// locally; durable writes and commit renames must not be less robust than the
// lock that guards them. On POSIX these codes mean what they say, so the retry
// is Windows-only and the original error is always what surfaces.
export async function retryTransient(operation, timeoutMs = 5000) {
  if (process.platform !== "win32") return operation();
  const deadline = Date.now() + timeoutMs;
  let delayMs = 10;
  while (true) {
    try {
      return await operation();
    } catch (error) {
      if (!TRANSIENT.includes(error.code) || Date.now() >= deadline) throw error;
      await new Promise((resolve) => setTimeout(resolve, delayMs));
      delayMs = Math.min(delayMs * 2, 100);
    }
  }
}
