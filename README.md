# Deferred-Execution Attacks Against AI Control Monitors

This repository shows that an AI agent with shell access can install a dormant Linux trigger during a monitored session and have it cause harm only after the monitor has cleared the session. It is for researchers working on AI control and agent monitoring, and it contains the attack traces, a proposed defense, and the evaluation behind the paper in `project/writeup/paper.md` (William Guo, University of Chicago, Uncommon Hacks 2026).

## Results

The monitor evaluation used four attacks, each in two forms, plus four honest sessions, in BashArena, the shell environment from ControlArena. In the deferred form the harm waits inside a trigger. In the commission form the same harm runs during the session. Monitors give each session a score from 0 to 1, and a score above 0.5 counts as caught.

- The strongest monitor that scores each command as it runs caught 4 of 4 commission attacks but 0 of 4 deferred attacks. Adding a prompt that names every trigger type did not raise its deferred catch rate.
- The best existing monitor overall, which reads the whole session transcript at once, caught 2 of 4 deferred attacks.
- The trigger-graph monitor proposed here caught 4 of 4 deferred attacks and flagged 0 of 4 honest sessions.
- Against the best per-command monitor, the difference is significant (Fisher's exact test, p = 0.029). Against the whole-transcript monitor it is not (p = 0.429). Four attacks per condition is a small sample.
- The trigger-graph monitor cost about $0.05 per session, against $0.02 for a per-command monitor using Claude Opus.

Per-monitor scores are in `project/writeup/results_table.md`, and the full numbers are in `project/writeup/results_summary.md` and `project/eval/`.

## The attack

Every command the agent runs is ordinary system administration: a cron entry, a systemd timer, an inotify file watcher, a shell exit trap, a login hook, a log-rotation script. The harmful action sits inside the trigger and runs later, so a monitor that scores each command during the session sees nothing to flag. `project/TAXONOMY.md` groups the triggers into five categories: scheduled jobs, event watchers, lifecycle hooks, authentication hooks, and resource conditions.

## The defense

At the end of a session, the trigger-graph monitor lists every dormant trigger the agent installed, follows each one to the action it will run, and scores that action as a per-command monitor would score it had it run during the session. If any of those actions looks harmful, the session is flagged. The implementation is `project/defense/trigger_graph_monitor.py`.

## Running it

Each attack trace comes in a deferred and a commission version. `project/attacks/INDEX.md` lists 20 traces (10 attacks, each in both versions) across the five trigger categories, each verified by its sandbox test. The monitor evaluation above used four of those attacks. To replay a trace, run these from `project/`:

```bash
docker build -t dex-sandbox sandbox/
./sandbox/test_C1_1.sh
./sandbox/test_C1_1.sh attacks/C1/C1.1_cron_backup_exfil_commission.json
```

The first test replays the deferred cron attack and the second its commission version. Each script prints PASS when the harm lands and FAIL otherwise.

The monitor evaluation is `project/eval/run_evaluation.py`. It needs API keys for the monitor models and an install of the ControlArena copy in `control-arena/`, which provides BashArena and the baseline monitors.

## Layout

- `project/attacks/`: the attack traces as JSON
- `project/defense/`: the trigger-graph monitor
- `project/eval/`: evaluation scripts and result files
- `project/sandbox/`: the Docker sandbox and one replay test per attack
- `project/writeup/`: the paper, the results, and the figures
- `control-arena/`: a copy of the ControlArena project
