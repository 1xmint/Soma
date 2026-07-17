export class SomaError extends Error {
  constructor(message, exitCode, code, details = undefined) {
    super(message);
    this.name = "SomaError";
    this.exitCode = exitCode;
    this.code = code;
    this.details = details;
  }
}

export function asSomaError(error) {
  if (error instanceof SomaError) return error;
  return new SomaError("internal failure; no partial success is claimed", 10, "INTERNAL_FAILURE", {
    cause: error instanceof Error ? error.message : String(error)
  });
}
