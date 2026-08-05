#!/usr/bin/env python3
"""
Independent falsifier for the reference evaluator's flow computation.

The brief's first failure pattern is "a check that confirms something adjacent
to the claim" -- a round trip agreeing with itself. So this deliberately does
NOT implement max-flow. It computes the MINIMUM CUT directly from its
definition, by enumerating every partition of the vertices that keeps the
source and sink apart and summing the capacity crossing forward:

    cut(S, T) = sum of c(u, v) for every edge with u in S and v in T

By the max-flow/min-cut theorem the maximum flow equals the minimum such cut.
Two implementations, two different algorithms, no shared code and no shared
assumptions -- one in JavaScript solving a flow problem, one in Python
enumerating subsets. If they agree, the agreement means something.

Exponential by design. Small instances only; that is the price of a check that
shares nothing with the thing it checks.

Usage:
    python mincut-falsifier.py network.json

The JSON is emitted by the JS side and carries the integer network exactly as
the evaluator built it, plus the flow value the evaluator computed.
Exit code 0 means the claim survived.
"""

import json
import sys
from itertools import combinations


def min_cut_by_enumeration(node_count, edges, source, sink):
    """Minimum cut, by trying every legal partition. No flow algorithm here."""
    others = [v for v in range(node_count) if v not in (source, sink)]
    best = None

    # Every subset of the remaining vertices joins the source side or does not.
    for size in range(len(others) + 1):
        for chosen in combinations(others, size):
            s_side = {source, *chosen}
            total = 0
            for u, v, c in edges:
                if u in s_side and v not in s_side:
                    total += c
            if best is None or total < best:
                best = total
    return best


def main(path):
    with open(path, "r", encoding="utf-8") as handle:
        payload = json.load(handle)

    failures = 0
    for case in payload["cases"]:
        node_count = case["node_count"]
        if node_count > case.get("max_nodes", 18):
            print(f"SKIP {case['name']}: {node_count} nodes is too many to enumerate")
            continue

        edges = [(e["u"], e["v"], e["c"]) for e in case["edges"]]
        expected = min_cut_by_enumeration(node_count, edges, case["source"], case["sink"])
        actual = case["flow"]

        if actual > expected:
            print(f"FAIL {case['name']}: evaluator returned {actual}, above the min cut {expected}")
            failures += 1
        elif actual != expected:
            # Below the cut is also wrong: max-flow/min-cut is an equality, and
            # a policy that under-reports is refusing standing that was honestly
            # earned, which harms the honest participant rather than the attacker.
            print(f"FAIL {case['name']}: evaluator returned {actual}, min cut is {expected}")
            failures += 1
        else:
            print(f"ok   {case['name']}: flow {actual} == min cut {expected}")

    if failures:
        print(f"\n{failures} failure(s)")
        return 1
    print("\n0 failure(s)")
    return 0


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(__doc__)
        raise SystemExit(2)
    raise SystemExit(main(sys.argv[1]))
