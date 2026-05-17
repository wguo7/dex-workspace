"""Fisher exact (two-sided) on deferred-catch contingency tables; write eval/significance.json."""

import json
import math
from pathlib import Path


def fisher_two_sided_pvalue(table: list[list[int]]) -> float:
    [[a, b], [c, d]] = table
    row1, row2 = a + b, c + d
    col1 = a + c
    n = row1 + row2

    def logp(x: int) -> float:
        y = row1 - x
        z = col1 - x
        w = row2 - z
        return (
            math.lgamma(row1 + 1)
            - math.lgamma(x + 1)
            - math.lgamma(y + 1)
            + math.lgamma(row2 + 1)
            - math.lgamma(z + 1)
            - math.lgamma(w + 1)
            - (math.lgamma(n + 1) - math.lgamma(col1 + 1) - math.lgamma(n - col1 + 1))
        )

    x_min = max(0, row1 - (b + d))
    x_max = min(row1, col1)
    probs: dict[int, float] = {}
    for x in range(x_min, x_max + 1):
        probs[x] = math.exp(logp(x))
    p_obs = probs[a]
    return sum(p for p in probs.values() if p <= p_obs + 1e-15)


def main() -> None:
    out_path = Path(__file__).resolve().parent / "significance.json"
    vs_per_step = [[4, 0], [0, 4]]
    vs_overall = [[4, 0], [2, 2]]
    p1 = fisher_two_sided_pvalue(vs_per_step)
    p2 = fisher_two_sided_pvalue(vs_overall)
    payload = {
        "vs_best_per_step": {
            "contingency": vs_per_step,
            "p_value": round(p1, 3),
        },
        "vs_best_overall": {
            "contingency": vs_overall,
            "p_value": round(p2, 3),
        },
    }
    out_path.write_text(json.dumps(payload, indent=2) + "\n")
    print(
        "Fisher exact (two-sided) trigger-graph vs best per-step (A/C/F): "
        f"p = {p1:.6f} (rounded {payload['vs_best_per_step']['p_value']:.3f})"
    )
    print(
        "Fisher exact (two-sided) trigger-graph vs best overall (G): "
        f"p = {p2:.6f} (rounded {payload['vs_best_overall']['p_value']:.3f})"
    )
    print(f"Wrote {out_path}")


if __name__ == "__main__":
    main()
