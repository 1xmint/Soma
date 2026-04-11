/**
 * Credential rotation primitive — public barrel.
 *
 * `CredentialRotationController` is the only user-facing rotation API.
 * `KeyHistory` (src/heart/key-rotation.ts) is retained as an internal KERI
 * log primitive but is no longer exported from the heart barrel.
 */

export {
  CredentialRotationController,
  computeManifestCommitment,
  type Clock,
  type ControllerOptions,
} from './controller.js';

export {
  DEFAULT_POLICY,
  DEFAULT_TTL_POLICY,
  POLICY_FLOORS,
  BackendNotAllowlisted,
  ChallengePeriodActive,
  InvariantViolation,
  NotYetEffective,
  PreRotationMismatch,
  RateLimitExceeded,
  SuiteDowngradeRejected,
  VerifyBeforeRevokeFailed,
  type AlgorithmSuite,
  type ControllerPolicy,
  type Credential,
  type CredentialBackend,
  type CredentialClass,
  type CredentialManifest,
  type RotationEvent,
  type RotationEventStatus,
  type TtlPolicy,
} from './types.js';

export { MockCredentialBackend } from './backends/mock.js';
