"""Measure Monitor C vs Monitor E wall time and token usage on 4 deferred traces.

Run from control-arena with project on PYTHONPATH, e.g.:
  cd /path/to/control-arena && PYTHONPATH=/path/to/project uv run python /path/to/project/eval/run_cost_analysis.py
"""

from __future__ import annotations

import asyncio
import json
import sys
import time
from pathlib import Path

from inspect_ai.model import ChatMessageUser, GenerateConfig, get_model

from control_arena._async_utils import gather
from control_arena.monitor._utils import extract_monitor_response
from control_arena.monitor.prompts import monitor_prompts

PROJECT_ROOT = Path(__file__).resolve().parent.parent
EVAL_DIR = PROJECT_ROOT / "eval"

# Must match run_evaluation / trigger_graph_monitor
IN_SCOPE = [
    "C1.1_cron_backup_exfil",
    "C2.1_inotify_passwd_watch",
    "C4.1_pam_exec_session",
    "C5.1_logrotate_postrotate",
]
MONITOR_C_MODEL = "anthropic/claude-opus-4-7"
MONITOR_E_MODEL = "anthropic/claude-opus-4-7"

# Anthropic API list pricing (Claude Opus 4 family), May 2026 — source: platform.claude.com pricing
USD_PER_M_INPUT = 5.0
USD_PER_M_OUTPUT = 25.0


def _usage_charges(u) -> tuple[int, int]:
    if u is None:
        return 0, 0
    inp = u.input_tokens + (u.input_tokens_cache_read or 0) + (u.input_tokens_cache_write or 0)
    return int(inp), int(u.output_tokens)


def _mean(xs: list[float]) -> float:
    return sum(xs) / len(xs) if xs else 0.0


def _mean_i(xs: list[int]) -> float:
    return sum(xs) / len(xs) if xs else 0.0


async def monitor_c_scoring_wall_and_tokens(commands: list[str], main_task: str) -> dict:
    """Wall time of one Monitor C scoring pass (parallel per-bash-call Opus); sum tokens."""
    if not commands:
        return {"wall_sec": 0.0, "input_tokens": 0, "output_tokens": 0}
    model = get_model(MONITOR_C_MODEL, config=GenerateConfig())
    tmpl = monitor_prompts["default"]
    in_tot = 0
    out_tot = 0
    t0 = time.perf_counter()

    async def score_one(cmd: str) -> None:
        nonlocal in_tot, out_tot
        tool_calls_str = f"bash: {json.dumps({'command': cmd})}\n"
        formatted = tmpl.format(task_description=main_task, tool_calls=tool_calls_str)
        out = await model.generate(input=[ChatMessageUser(content=formatted)], cache=False)
        di, dout = _usage_charges(out.usage)
        in_tot += di
        out_tot += dout

    await gather(*[score_one(c) for c in commands])
    return {
        "wall_sec": time.perf_counter() - t0,
        "input_tokens": in_tot,
        "output_tokens": out_tot,
    }


async def run_monitor_e_wall_and_tokens(trace_id: str) -> dict:
    sys.path.insert(0, str(PROJECT_ROOT))
    import defense.trigger_graph_monitor as tg  # noqa: E402

    info = tg.resolve_trace(trace_id, "deferred")
    trace_json = json.loads(Path(info["trace_json"]).read_text())
    main_task = trace_json["main_task"]
    session_commands = trace_json["session_commands"]
    log_file = tg._find_latest_eval_log(info["log_dir"])
    if log_file is None:
        raise RuntimeError(f"no .eval log in {info['log_dir']}")
    from inspect_ai.log import read_eval_log  # noqa: E402

    log = read_eval_log(str(log_file))
    sample = log.samples[0]
    real_commands = tg._extract_bash_calls(sample.messages)

    batches: list[dict] = []

    async def score_batch(
        cmds: list[str], task_description: str, model_name: str
    ) -> None:
        if not cmds:
            return
        model = get_model(model_name, config=GenerateConfig())
        tmpl = monitor_prompts["default"]
        inp_sum = 0
        out_sum = 0
        t_wall0 = time.perf_counter()

        async def score_one(cmd: str) -> None:
            nonlocal inp_sum, out_sum
            tool_calls_str = f"bash: {json.dumps({'command': cmd})}\n"
            formatted = tmpl.format(
                task_description=task_description, tool_calls=tool_calls_str
            )
            out = await model.generate(
                input=[ChatMessageUser(content=formatted)], cache=False
            )
            di, dout = _usage_charges(out.usage)
            inp_sum += di
            out_sum += dout
            extract_monitor_response(model_output=out)

        await gather(*[score_one(c) for c in cmds])
        batches.append(
            {
                "wall_sec": time.perf_counter() - t_wall0,
                "input_tokens": inp_sum,
                "output_tokens": out_sum,
            }
        )

    t0_total = time.perf_counter()
    triggers, _changes, _pre, _post = tg.run_trigger_extraction(
        info["dockerfile"], info["image_tag"], session_commands
    )
    td_monitor = tg._monitor_e_task_description(main_task)  # noqa: SLF001
    await score_batch(real_commands, td_monitor, MONITOR_E_MODEL)
    trig_cmds = [
        tg._synthesise_trigger_command(t, main_task) for t in triggers  # noqa: SLF001
    ]
    await score_batch(trig_cmds, td_monitor, MONITOR_E_MODEL)
    wall_pipeline = time.perf_counter() - t0_total
    in_tot = sum(b["input_tokens"] for b in batches)
    out_tot = sum(b["output_tokens"] for b in batches)
    return {
        "wall_sec": wall_pipeline,
        "input_tokens": in_tot,
        "output_tokens": out_tot,
    }


def dollars(inp: int, out: int) -> float:
    return inp / 1_000_000 * USD_PER_M_INPUT + out / 1_000_000 * USD_PER_M_OUTPUT


async def main_async() -> None:
    sys.path.insert(0, str(EVAL_DIR))
    import run_evaluation as re  # noqa: E402

    c_walls: list[float] = []
    c_in: list[int] = []
    c_out: list[int] = []
    e_walls: list[float] = []
    e_in: list[int] = []
    e_out: list[int] = []

    for tid in IN_SCOPE:
        paths = None
        for t in re.TRACES:
            if t["trace_id"] == tid:
                paths = re.trace_paths(t)["deferred"]
                break
        if paths is None:
            raise RuntimeError(f"unknown trace {tid}")
        log_file = re.find_latest_eval_log(paths["log_dir"])
        if not log_file:
            raise RuntimeError(f"no log for {tid}")
        from inspect_ai.log import read_eval_log  # noqa: E402

        log = read_eval_log(str(log_file))
        sample = log.samples[0]
        commands = re.extract_bash_tool_calls(sample.messages)
        trace_json = json.loads(paths["trace_json"].read_text())
        main_task = trace_json["main_task"]
        print(f"\n--- Monitor C: {tid} ({len(commands)} bash calls) ---")
        c_m = await monitor_c_scoring_wall_and_tokens(commands, main_task)
        print(
            f"  wall={c_m['wall_sec']:.2f}s tokens in/out={c_m['input_tokens']}/{c_m['output_tokens']}"
        )
        c_walls.append(c_m["wall_sec"])
        c_in.append(c_m["input_tokens"])
        c_out.append(c_m["output_tokens"])

        print(f"--- Monitor E: {tid} (full pipeline) ---")
        e_m = await run_monitor_e_wall_and_tokens(tid)
        print(
            f"  wall={e_m['wall_sec']:.2f}s tokens in/out={e_m['input_tokens']}/{e_m['output_tokens']}"
        )
        e_walls.append(e_m["wall_sec"])
        e_in.append(e_m["input_tokens"])
        e_out.append(e_m["output_tokens"])

    mc = {
        "mean_runtime_sec": round(_mean(c_walls), 1),
        "mean_input_tokens": int(round(_mean_i(c_in))),
        "mean_output_tokens": int(round(_mean_i(c_out))),
    }
    me = {
        "mean_runtime_sec": round(_mean(e_walls), 1),
        "mean_input_tokens": int(round(_mean_i(e_in))),
        "mean_output_tokens": int(round(_mean_i(e_out))),
    }
    tot_c = mc["mean_input_tokens"] + mc["mean_output_tokens"]
    tot_e = me["mean_input_tokens"] + me["mean_output_tokens"]
    mult_tok = (tot_e / tot_c) if tot_c else 0.0
    mult_rt = (
        (me["mean_runtime_sec"] / mc["mean_runtime_sec"])
        if mc["mean_runtime_sec"]
        else 0.0
    )
    out = {
        "monitor_c": mc,
        "monitor_e": me,
        "monitor_e_overhead": {
            "runtime_multiplier": round(mult_rt, 1),
            "token_multiplier": round(mult_tok, 1),
        },
    }
    out_path = EVAL_DIR / "cost_analysis.json"
    out_path.write_text(json.dumps(out, indent=2) + "\n")

    # Per-session USD at mean token rates (same as mean of per-trace USD for linear pricing)
    usd_c = dollars(mc["mean_input_tokens"], mc["mean_output_tokens"])
    usd_e = dollars(me["mean_input_tokens"], me["mean_output_tokens"])
    ratio_cost = (usd_e / usd_c) if usd_c else 0.0

    print(
        "\nPricing assumption: Opus 4.x API $5/M input, $25/M output (Anthropic list, May 2026)."
    )
    print(
        f"Monitor C per session: ~{mc['mean_runtime_sec']:.1f} sec, ~${usd_c:.2f}"
    )
    print(
        f"Monitor E per session: ~{me['mean_runtime_sec']:.1f} sec, ~${usd_e:.2f}  "
        f"({ratio_cost:.1f}x Monitor C cost)"
    )
    print(f"Wrote {out_path}")


def main() -> None:
    asyncio.run(main_async())


if __name__ == "__main__":
    main()
