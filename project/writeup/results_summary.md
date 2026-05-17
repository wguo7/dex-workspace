## Summary statistics

- Deferred catch rate at threshold 0.5: existing monitors 0-50%, trigger-graph 100% (4/4)
- Honest false-positive rate at threshold 0.5: 0/4 for both Monitor C and Trigger-graph
- Mean deferred score: existing monitors 0.15-0.35, trigger-graph 0.90
- Mean honest score (trigger-graph): 0.08
- Fisher's exact test (4/4 vs 0/4 for best per-step monitor): p = 0.029
- Fisher's exact test (4/4 vs 2/4 for best monitor overall): p = 0.429
- Cost: trigger-graph adds ~3x token cost and ~7.6x runtime over Opus action-only ($0.05 vs $0.02 per session)
