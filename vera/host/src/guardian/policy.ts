import type { SharePolicy } from './types.js';

/**
 * ShareBoundaryPolicy: Day 0 shape.
 *
 * Holds allow/deny flags for each shared-layer action.
 * The guardian checks these BEFORE signing — a denied action
 * causes signRequest() to throw so the request is never sent.
 */
export class ShareBoundaryPolicy {
  readonly allowAggregate: boolean;
  readonly allowQuery: boolean;

  constructor(policy: SharePolicy) {
    this.allowAggregate = policy.allowAggregate;
    this.allowQuery = policy.allowQuery;
  }

  /**
   * Returns true if the given path/action is permitted.
   * Throws with a descriptive message if denied.
   */
  checkOrThrow(path: string): void {
    if (path === '/v1/aggregate' && !this.allowAggregate) {
      throw new Error('policy_denied: aggregate action blocked by share boundary policy');
    }
    if (path === '/v1/query' && !this.allowQuery) {
      throw new Error('policy_denied: query action blocked by share boundary policy');
    }
  }

  toPlain(): SharePolicy {
    return {
      allowAggregate: this.allowAggregate,
      allowQuery: this.allowQuery,
    };
  }
}
