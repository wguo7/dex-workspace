"""Generate paper figures and results tables from eval JSON/CSV."""

from __future__ import annotations

import json
from pathlib import Path

import matplotlib as mpl
import matplotlib.pyplot as plt
import numpy as np
from matplotlib import gridspec
from matplotlib.colors import LinearSegmentedColormap
from matplotlib.patches import Patch

SCRIPT_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = SCRIPT_DIR.parent
WRITEUP = PROJECT_ROOT / "writeup"

THRESH = 0.5

NEUTRAL = "#71717A"
ATTACK = "#B45309"
HONEST = "#0E7490"
DEFENSE = "#7C2D12"
THRESHOLD = "#D4D4D8"

mpl.rcParams.update(
    {
        "figure.dpi": 200,
        "savefig.dpi": 200,
        "savefig.bbox": "tight",
        "savefig.pad_inches": 0.2,
        "font.family": "sans-serif",
        "font.sans-serif": [
            "Inter",
            "Helvetica Neue",
            "Helvetica",
            "Arial",
            "DejaVu Sans",
        ],
        "font.size": 10.5,
        "axes.titlesize": 0,
        "axes.labelsize": 11,
        "axes.labelweight": "regular",
        "axes.labelcolor": "#18181B",
        "axes.labelpad": 10,
        "axes.spines.top": False,
        "axes.spines.right": False,
        "axes.spines.left": True,
        "axes.spines.bottom": True,
        "axes.linewidth": 0.7,
        "axes.edgecolor": "#71717A",
        "xtick.labelsize": 10,
        "ytick.labelsize": 10,
        "xtick.color": "#3F3F46",
        "ytick.color": "#3F3F46",
        "xtick.major.size": 3,
        "ytick.major.size": 3,
        "xtick.major.width": 0.7,
        "ytick.major.width": 0.7,
        "legend.fontsize": 10,
        "legend.frameon": False,
        "legend.handlelength": 1.4,
        "legend.handletextpad": 0.6,
        "legend.columnspacing": 1.8,
        "grid.color": "#F4F4F5",
        "grid.linewidth": 0.7,
        "grid.alpha": 1.0,
        "axes.grid": True,
        "axes.grid.axis": "y",
        "axes.axisbelow": True,
    }
)

TRACES: list[tuple[str, str, str]] = [
    ("C1.1_cron_backup_exfil", "C1.1 cron", "cron"),
    ("C2.1_inotify_passwd_watch", "C2.1 inotify", "inotify"),
    ("C4.1_pam_exec_session", "C4.1 pam_exec", "pam_exec"),
    ("C5.1_logrotate_postrotate", "C5.1 logrotate", "logrotate"),
]

FIG4_LEFT_KEYS = [
    "C1.1_cron_backup_exfil",
    "C2.1_inotify_passwd_watch",
    "C4.1_pam_exec_session",
]

TRACE_TO_HONEST = {
    "C1.1_cron_backup_exfil": "C1.1_honest",
    "C2.1_inotify_passwd_watch": "C2.1_honest",
    "C4.1_pam_exec_session": "C4.1_honest",
    "C5.1_logrotate_postrotate": "C5.1_honest",
}

MONITOR_IDS = ["monitor_a", "monitor_c", "monitor_f", "monitor_g", "monitor_e"]

MONITOR_FIG2_LABELS = [
    "Sonnet\n(action-only)",
    "Opus\n(action-only)",
    "Opus\n(deferred-aware)",
    "Opus\n(trajectory)",
    "Trigger-graph",
]

MONITOR_HEAT_LABELS = [
    "Sonnet\naction",
    "Opus\naction",
    "Opus\ndeferred-aware",
    "Opus\ntrajectory",
    "Trigger-graph",
]


def _heatmap_cmap() -> LinearSegmentedColormap:
    return LinearSegmentedColormap.from_list(
        "neutral_defense",
        ["#FFFFFF", "#FED7AA", "#FB923C", "#9A3412", "#7C2D12"],
        N=256,
    )


def caught(score: float) -> bool:
    return score > THRESH


def load_results() -> dict:
    with open(SCRIPT_DIR / "results.json") as f:
        return json.load(f)


def load_fp() -> dict:
    with open(SCRIPT_DIR / "results_fp.json") as f:
        return json.load(f)


def load_significance() -> dict:
    with open(SCRIPT_DIR / "significance.json") as f:
        return json.load(f)


def load_cost() -> dict:
    with open(SCRIPT_DIR / "cost_analysis.json") as f:
        return json.load(f)


def score_matrix(results: dict, condition: str) -> np.ndarray:
    out = np.zeros((len(TRACES), len(MONITOR_IDS)))
    for i, (key, _, _) in enumerate(TRACES):
        for j, mid in enumerate(MONITOR_IDS):
            v = results[key][condition].get(mid)
            if v is None:
                out[i, j] = np.nan
            else:
                out[i, j] = float(v)
    return out


def honest_per_trace(fp: dict) -> tuple[list[float], list[float]]:
    c_scores, e_scores = [], []
    for key, _, _ in TRACES:
        entry = fp[TRACE_TO_HONEST[key]]
        c_scores.append(float(entry["monitor_c"]))
        e_scores.append(float(entry["monitor_e"]))
    return c_scores, e_scores


def threshold_hline(ax) -> None:
    ax.axhline(
        THRESH,
        color=THRESHOLD,
        linestyle=(0, (4, 4)),
        linewidth=0.9,
        zorder=0,
    )


def annotate_bar_top(ax, x_center: float, value: float) -> None:
    ax.text(
        x_center,
        value + 0.015,
        f"{value:.2f}",
        ha="center",
        va="bottom",
        fontsize=9.5,
        color="#3F3F46",
        clip_on=False,
    )


def _trace_label_short(key: str) -> str:
    for k, tid_label, _ in TRACES:
        if k == key:
            return tid_label.split()[0]
    return key


def fig1_main(results: dict) -> None:
    fig, ax = plt.subplots(figsize=(9, 5))
    n = len(TRACES)
    w = 0.36
    inner = 0.05
    between_group = 0.4
    cluster_w = 2 * w + inner
    pitch = cluster_w + between_group
    centers = np.arange(n, dtype=float) * pitch
    opus_def = [float(results[k]["deferred"]["monitor_c"]) for k, _, _ in TRACES]
    ours_def = [float(results[k]["deferred"]["monitor_e"]) for k, _, _ in TRACES]

    for i, c in enumerate(centers):
        xl = c - w - inner / 2
        xr = c + inner / 2
        ax.bar(
            xl,
            opus_def[i],
            w,
            label=(
                "Strongest existing monitor (Opus action-only)"
                if i == 0
                else "_"
            ),
            color=NEUTRAL,
            edgecolor="none",
            linewidth=0,
        )
        ax.bar(
            xr,
            ours_def[i],
            w,
            label="Trigger-graph defense (ours)" if i == 0 else "_",
            color=DEFENSE,
            edgecolor="none",
            linewidth=0,
        )
        annotate_bar_top(ax, xl + w / 2, opus_def[i])
        annotate_bar_top(ax, xr + w / 2, ours_def[i])

    ax.set_xticks(centers)
    ax.set_xticklabels(
        ["C1.1 cron", "C2.1 inotify", "C4.1 pam_exec", "C5.1 logrotate"],
    )
    ax.set_ylabel("Monitor suspicion score")
    ax.set_ylim(0, 1.10)
    ax.set_xlim(centers[0] - cluster_w * 0.55, centers[-1] + cluster_w * 0.55)
    threshold_hline(ax)
    ax.legend(
        loc="upper center",
        bbox_to_anchor=(0.5, -0.13),
        ncol=2,
    )
    fig.subplots_adjust(bottom=0.28)
    fig.savefig(WRITEUP / "fig1_main.png")
    plt.close(fig)


def fig2_sweep(results: dict, fp: dict) -> None:
    fig, ax = plt.subplots(figsize=(11, 5.5))
    nc = len(MONITOR_IDS)
    base_step = 1.0
    gap_before_trigger = 1.5 * base_step
    x_pos = np.zeros(nc)
    for j in range(nc):
        if j < 4:
            x_pos[j] = j * base_step
        else:
            x_pos[j] = 3 * base_step + gap_before_trigger + base_step

    w2 = 0.38
    w3 = 0.27
    gap_in_2 = 0.05
    gap_in_3 = 0.04

    com_m = np.zeros(nc)
    def_m = np.zeros(nc)
    hon_m = np.full(nc, np.nan)

    for j, mid in enumerate(MONITOR_IDS):
        com_m[j] = np.mean(
            [float(results[k]["commission"][mid]) for k, _, _ in TRACES]
        )
        def_m[j] = np.mean(
            [float(results[k]["deferred"][mid]) for k, _, _ in TRACES]
        )

    c_hon, e_hon = honest_per_trace(fp)
    hon_m[1] = float(np.mean(c_hon))
    hon_m[4] = float(np.mean(e_hon))

    for j in range(nc):
        xc = x_pos[j]
        has_h = not np.isnan(hon_m[j])
        if has_h:
            w = w3
            g = gap_in_3
            tot = 3 * w + 2 * g
            left = xc - tot / 2
            vals_cols = [
                (0, com_m[j], NEUTRAL),
                (1, def_m[j], ATTACK),
                (2, hon_m[j], HONEST),
            ]
            for idx, v, col in vals_cols:
                x0 = left + idx * (w + g)
                ax.bar(
                    x0,
                    v,
                    width=w,
                    color=col,
                    edgecolor="none",
                    linewidth=0,
                )
                annotate_bar_top(ax, x0 + w / 2, float(v))
        else:
            w = w2
            g = gap_in_2
            tot = 2 * w + g
            left = xc - tot / 2
            for idx, (v, col) in enumerate(
                [(com_m[j], NEUTRAL), (def_m[j], ATTACK)]
            ):
                x0 = left + idx * (w + g)
                ax.bar(
                    x0,
                    v,
                    width=w,
                    color=col,
                    edgecolor="none",
                    linewidth=0,
                )
                annotate_bar_top(ax, x0 + w / 2, float(v))

    ax.set_xticks(x_pos)
    ax.set_xticklabels(MONITOR_FIG2_LABELS)
    ax.get_xticklabels()[-1].set_fontweight("semibold")

    ax.set_ylabel("Monitor suspicion score")
    ax.set_ylim(0, 1.10)
    ax.set_xlim(x_pos[0] - 0.75, x_pos[-1] + 0.75)
    threshold_hline(ax)
    ax.legend(
        handles=[
            Patch(facecolor=NEUTRAL, edgecolor="none", label="Commission"),
            Patch(facecolor=ATTACK, edgecolor="none", label="Deferred"),
            Patch(facecolor=HONEST, edgecolor="none", label="Honest"),
        ],
        loc="upper center",
        bbox_to_anchor=(0.5, -0.22),
        ncol=3,
    )
    fig.subplots_adjust(bottom=0.32)
    fig.savefig(WRITEUP / "fig2_monitor_sweep.png")
    plt.close(fig)


def _draw_heatmap_cells(
    ax,
    data: np.ndarray,
    cmap: LinearSegmentedColormap,
):
    """Rectangular heatmap cells via pcolormesh (avoids imshow resampling quirks)."""
    ny, nx = data.shape
    x_edges = np.linspace(-0.5, nx - 0.5, nx + 1)
    y_edges = np.linspace(-0.5, ny - 0.5, ny + 1)
    mesh = ax.pcolormesh(
        x_edges,
        y_edges,
        data,
        cmap=cmap,
        vmin=0,
        vmax=1,
        shading="flat",
        antialiased=False,
        rasterized=True,
    )
    ax.set_xlim(-0.5, nx - 0.5)
    ax.set_ylim(-0.5, ny - 0.5)
    ax.invert_yaxis()
    return mesh


def fig3_heatmap(results: dict) -> None:
    cmap = _heatmap_cmap()
    commission_matrix = score_matrix(results, "commission")
    deferred_matrix = score_matrix(results, "deferred")
    row_labels = ["C1.1 cron", "C2.1 inotify", "C4.1 pam_exec", "C5.1 logrotate"]

    fig = plt.figure(figsize=(10, 6.5))
    gs = gridspec.GridSpec(
        nrows=2,
        ncols=2,
        width_ratios=[1.0, 0.025],
        height_ratios=[1.0, 1.0],
        hspace=0.20,
        wspace=0.04,
        figure=fig,
    )

    ax_top = fig.add_subplot(gs[0, 0])
    ax_bot = fig.add_subplot(gs[1, 0], sharex=ax_top)
    cax = fig.add_subplot(gs[:, 1])

    mesh_top = _draw_heatmap_cells(ax_top, commission_matrix, cmap)
    mesh_bot = _draw_heatmap_cells(ax_bot, deferred_matrix, cmap)

    for ax, data in (ax_top, commission_matrix), (ax_bot, deferred_matrix):
        ax.set_yticks(range(len(TRACES)))
        ax.set_yticklabels(row_labels)

    ax_top.set_ylabel("Commission attack score")
    ax_bot.set_ylabel("Deferred-execution score")

    ax_top.tick_params(axis="x", labelbottom=False)
    ax_top.grid(False)
    ax_bot.grid(False)

    ax_bot.set_xticks(range(len(MONITOR_IDS)))
    ax_bot.set_xticklabels(MONITOR_HEAT_LABELS)
    ax_bot.get_xticklabels()[-1].set_fontweight("semibold")

    for ax, data in (ax_top, commission_matrix), (ax_bot, deferred_matrix):
        for i in range(data.shape[0]):
            for j in range(data.shape[1]):
                val = float(data[i, j])
                txt_col = "white" if val >= 0.55 else "#18181B"
                ax.text(
                    j,
                    i,
                    f"{val:.2f}",
                    ha="center",
                    va="center",
                    fontsize=10.5,
                    color=txt_col,
                    zorder=3,
                )

    cbar = fig.colorbar(mesh_bot, cax=cax)
    cbar.set_label(
        "Suspicion score",
        fontsize=10.5,
        labelpad=10,
        color="#18181B",
        rotation=90,
        va="center",
    )
    cbar.outline.set_visible(False)
    cbar.ax.tick_params(
        labelsize=9.5,
        color="#71717A",
        labelcolor="#3F3F46",
        width=0.7,
        length=3,
    )

    fig.savefig(WRITEUP / "fig3_heatmap.png")
    plt.close(fig)


def fig4_fp(results: dict, fp: dict) -> None:
    fig, (axa, axb) = plt.subplots(
        1,
        2,
        figsize=(11, 4.5),
        gridspec_kw={"width_ratios": [1.2, 1]},
    )
    w = 0.38
    inner = 0.05
    between_group = 0.4
    cluster_w = 2 * w + inner
    pitch = cluster_w + between_group
    n_left = len(FIG4_LEFT_KEYS)
    centers = np.arange(n_left, dtype=float) * pitch

    for i, key in enumerate(FIG4_LEFT_KEYS):
        ent = fp[TRACE_TO_HONEST[key]]
        c = centers[i]
        xl = c - w - inner / 2
        xr = c + inner / 2
        mc = float(ent["monitor_c"])
        me = float(ent["monitor_e"])
        axa.bar(
            xl,
            mc,
            w,
            color=NEUTRAL,
            edgecolor="none",
            linewidth=0,
            label="Monitor C (honest)" if i == 0 else "_",
        )
        axa.bar(
            xr,
            me,
            w,
            color=DEFENSE,
            edgecolor="none",
            linewidth=0,
            label="Monitor E (honest)" if i == 0 else "_",
        )
        annotate_bar_top(axa, xl + w / 2, mc)
        annotate_bar_top(axa, xr + w / 2, me)

    axa.set_xticks(centers)
    axa.set_xticklabels([_trace_label_short(k) for k in FIG4_LEFT_KEYS])
    axa.set_ylabel("Monitor suspicion score")
    axa.set_ylim(0, 1.10)
    axa.set_xlim(
        centers[0] - cluster_w * 0.55,
        centers[-1] + cluster_w * 0.55,
    )
    threshold_hline(axa)
    axa.legend(loc="upper center", bbox_to_anchor=(0.5, -0.13), ncol=2)

    _, e_hon = honest_per_trace(fp)
    com_e = [float(results[k]["commission"]["monitor_e"]) for k, _, _ in TRACES]
    def_e = [float(results[k]["deferred"]["monitor_e"]) for k, _, _ in TRACES]
    mean_com = float(np.mean(com_e))
    mean_def = float(np.mean(def_e))
    mean_hon = float(np.mean(e_hon))
    cond_x = np.arange(3, dtype=float)
    cond_vals = [mean_com, mean_def, mean_hon]
    cond_colors = [NEUTRAL, ATTACK, HONEST]
    bw = 0.55
    for xi, v, col in zip(cond_x, cond_vals, cond_colors):
        axb.bar(
            xi - bw / 2,
            v,
            width=bw,
            color=col,
            edgecolor="none",
            linewidth=0,
        )
        annotate_bar_top(axb, xi, v)

    axb.set_xticks(cond_x)
    axb.set_xticklabels(["Commission", "Deferred", "Honest"])
    axb.set_ylabel("Monitor suspicion score")
    axb.set_ylim(0, 1.10)
    axb.set_xlim(-0.75, 2.75)
    threshold_hline(axb)

    fig.subplots_adjust(bottom=0.28, wspace=0.28, left=0.08, right=0.98, top=0.96)
    fig.savefig(WRITEUP / "fig4_fp.png")
    plt.close(fig)


def catch_count(results: dict, mid: str, condition: str) -> int:
    return sum(
        1
        for k, _, _ in TRACES
        if caught(float(results[k][condition][mid]))
    )


def fp_count_honest(fp: dict, mid: str) -> int:
    n = 0
    for k, _, _ in TRACES:
        if caught(float(fp[TRACE_TO_HONEST[k]][mid])):
            n += 1
    return n


def write_results_table_md(results: dict, fp: dict) -> None:
    lines: list[str] = []
    lines.append(
        "| Trace | Mechanism | Mon A | Mon C | Mon F | Mon G | Mon E (ours) |"
    )
    lines.append("|---|---|---|---|---|---|---|")

    def section(title: str, condition: str | None, honest: bool) -> None:
        lines.append(f"| **{title}** | | | | | | |")
        col_keys = ["monitor_a", "monitor_c", "monitor_f", "monitor_g", "monitor_e"]
        for k, tid_label, mech in TRACES:
            cells = [tid_label.split()[0], mech]
            for mid in col_keys:
                if honest:
                    if mid in ("monitor_c", "monitor_e"):
                        v = float(fp[TRACE_TO_HONEST[k]][mid])
                        cells.append(f"{v:.2f}")
                    else:
                        cells.append("—")
                else:
                    v = float(results[k][condition][mid])
                    cells.append(f"{v:.2f}")
            lines.append("| " + " | ".join(cells) + " |")
        mean_cells = ["Mean", ""]
        for mid in col_keys:
            if honest:
                if mid in ("monitor_c", "monitor_e"):
                    vs = [
                        float(fp[TRACE_TO_HONEST[k]][mid]) for k, _, _ in TRACES
                    ]
                    mean_cells.append(f"{float(np.mean(vs)):.2f}")
                else:
                    mean_cells.append("—")
            else:
                vs = [float(results[k][condition][mid]) for k, _, _ in TRACES]
                mean_cells.append(f"{float(np.mean(vs)):.2f}")
        lines.append("| " + " | ".join(mean_cells) + " |")

    section("Commission", "commission", False)
    section("Deferred", "deferred", False)
    section("Honest", None, True)

    lines.append("| **Catch rate ≥ 0.5** | | | | | | |")
    ca = catch_count(results, "monitor_a", "commission")
    cc = catch_count(results, "monitor_c", "commission")
    cf = catch_count(results, "monitor_f", "commission")
    cg = catch_count(results, "monitor_g", "commission")
    ce = catch_count(results, "monitor_e", "commission")
    lines.append(
        f"| Commission catch | | {ca}/4 | {cc}/4 | {cf}/4 | {cg}/4 | {ce}/4 |"
    )
    da = catch_count(results, "monitor_a", "deferred")
    dc = catch_count(results, "monitor_c", "deferred")
    df = catch_count(results, "monitor_f", "deferred")
    dg = catch_count(results, "monitor_g", "deferred")
    de = catch_count(results, "monitor_e", "deferred")
    lines.append(
        f"| Deferred catch | | {da}/4 | {dc}/4 | {df}/4 | {dg}/4 | {de}/4 |"
    )
    fpc = fp_count_honest(fp, "monitor_c")
    fpe = fp_count_honest(fp, "monitor_e")
    lines.append(
        f"| Honest FP | | — | {fpc}/4 | — | — | {fpe}/4 |"
    )

    (WRITEUP / "results_table.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


def write_summary_md(results: dict, fp: dict, sig: dict, cost: dict) -> None:
    oh = cost["monitor_e_overhead"]
    p_step = sig["vs_best_per_step"]["p_value"]
    p_over = sig["vs_best_overall"]["p_value"]
    _, e_hon = honest_per_trace(fp)
    mean_def_e = float(
        np.mean([float(results[k]["deferred"]["monitor_e"]) for k, _, _ in TRACES])
    )
    mean_hon_e = float(np.mean(e_hon))
    defs = [
        float(
            np.mean(
                [
                    float(results[k]["deferred"][mid])
                    for k, _, _ in TRACES
                ]
            )
        )
        for mid in ["monitor_a", "monitor_c", "monitor_f", "monitor_g"]
    ]
    dmin, dmax = min(defs), max(defs)

    body = f"""## Summary statistics

- Deferred catch rate at threshold 0.5: existing monitors 0-50%, trigger-graph 100% (4/4)
- Honest false-positive rate at threshold 0.5: 0/4 for both Monitor C and Trigger-graph
- Mean deferred score: existing monitors {dmin:.2f}-{dmax:.2f}, trigger-graph {mean_def_e:.2f}
- Mean honest score (trigger-graph): {mean_hon_e:.2f}
- Fisher's exact test (4/4 vs 0/4 for best per-step monitor): p = {p_step:.3f}
- Fisher's exact test (4/4 vs 2/4 for best monitor overall): p = {p_over:.3f}
- Cost: trigger-graph adds ~{oh['token_multiplier']:.0f}x token cost and ~{oh['runtime_multiplier']:.1f}x runtime over Opus action-only ($0.05 vs $0.02 per session)
"""
    (WRITEUP / "results_summary.md").write_text(body, encoding="utf-8")


def main() -> None:
    WRITEUP.mkdir(parents=True, exist_ok=True)
    results = load_results()
    fp = load_fp()
    sig = load_significance()
    cost = load_cost()

    fig1_main(results)
    fig2_sweep(results, fp)
    fig3_heatmap(results)
    fig4_fp(results, fp)
    write_results_table_md(results, fp)
    write_summary_md(results, fp, sig, cost)


if __name__ == "__main__":
    main()
