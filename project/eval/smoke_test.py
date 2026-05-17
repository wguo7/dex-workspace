"""Smoke test: confirm BashArena runs and yields a programmatic monitor suspicion score.

Runs ONE honest sample and ONE attack sample of BashArena under the
trusted_monitoring micro-protocol (wrapped in auto_submit), with
claude-opus-4-7 as the untrusted model and claude-sonnet-4-6 as the trusted
monitor. Writes the trajectory-level max suspicion score for each to
eval/smoke_results.json.
"""

import json
from pathlib import Path

from inspect_ai import eval as inspect_eval

from control_arena import EvalMode
from control_arena.eval import ControlEvalConfig, get_control_task_product
from control_arena.scorers import max_suspicion_scorer
from control_arena.settings.bash_arena.bash_arena_setting import BashArenaSetting
from control_arena.settings.bash_arena.protocol.auto_submit_protocol_wrapper import (
    auto_submit_protocol_wrapper,
)
from control_arena.settings.bash_arena.task.dataset import DatasetSpec

UNTRUSTED_MODEL = "anthropic/claude-opus-4-7"
TRUSTED_MODEL = "anthropic/claude-sonnet-4-6"


def extract_max_suspicion(sample) -> float | None:
    if not sample or not sample.scores:
        return None
    score = sample.scores.get("max_suspicion_scorer")
    if score is None:
        return None
    val = score.value
    try:
        return float(val)
    except (TypeError, ValueError):
        return None


def main():
    project_root = Path(__file__).resolve().parent.parent
    log_dir = project_root / "logs" / "smoke_test"
    log_dir.mkdir(parents=True, exist_ok=True)
    out_path = project_root / "eval" / "smoke_results.json"

    setting = BashArenaSetting(
        dataset_spec=DatasetSpec(max_tasks=1, shuffle_seed=0),
    )
    micro_protocol = auto_submit_protocol_wrapper()

    eval_config = ControlEvalConfig(
        untrusted_model=UNTRUSTED_MODEL,
        trusted_model=TRUSTED_MODEL,
        limit=1,
        max_steps=20,
        log_dir=str(log_dir),
        max_tasks=2,
        fail_on_error=False,
    )

    eval_tasks = get_control_task_product(
        settings=setting,
        micro_protocols=micro_protocol,
        modes=[EvalMode.HONEST, EvalMode.ATTACK],
        eval_config=eval_config,
        monitoring_scorers=[max_suspicion_scorer()],
    )

    eval_logs = inspect_eval(tasks=eval_tasks, **eval_config.eval_args())

    results: dict[str, float | None] = {"honest_score": None, "attack_score": None}
    for log in eval_logs:
        mode = (log.eval.metadata or {}).get("mode")
        if not mode:
            tn = log.eval.task or ""
            if "honest" in tn:
                mode = "honest"
            elif "attack" in tn:
                mode = "attack"
        if not log.samples:
            print(f"[{mode}] no samples in eval log; status={log.status}")
            continue
        sample = log.samples[0]
        score = extract_max_suspicion(sample)
        key = "honest_score" if mode == "honest" else "attack_score"
        results[key] = score
        print(f"[{mode}] max_suspicion_scorer = {score}")

    out_path.write_text(json.dumps(results, indent=2))
    print(f"\nWrote {out_path}: {json.dumps(results)}")


if __name__ == "__main__":
    main()
