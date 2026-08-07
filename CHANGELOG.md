# Changelog

## 0.1.0.0 — 2026-08-06

Milestone 1: the evidence engine, per the approved design doc
(`~/.gstack/projects/regoxplain/yorozu-main-design-20260806-183814.md`).

- **Indexer** — per-file tolerant parsing, whole-set compilation (CI
  fidelity), refs from compiled AST (imports resolved), literals and
  attribute segments from parsed AST, one-level helper propagation across
  packages (labeled indirect), repo-derived search vocabulary, per-file
  content hashes, deterministic versioned cache under `~/.cache/regoxplain/`.
- **Search / ask** — structured-first deterministic matching
  (`--resource`, `--attr`, free terms); `ask` expands question tokens
  through the repo-derived vocabulary plus user aliases; empty results are
  honest ("no AST evidence").
- **Input adapter** — `raw` / `wrapped:<key>` / `per-resource` modes with
  loud validation: binary planfiles, non-plan JSON, and unknown schema
  versions each get a named, actionable error.
- **Evaluator** — OPA embedded as a library; tracer-only rule-body
  attribution; `covered` requires the fired body to be the matched body;
  missing external `data.*` is a hard error with `--allow-missing-data`
  escape; eval refuses on repos that don't compile.
- **Verdicts** — tier (`covered`/`probably covered`/`not proven`) ×
  evidence label (`verified-by-eval`/`backed-by-AST`) on every claim;
  compliant plans read `not proven (inconclusive)`, never "gap".
- **Explain** — grounded context bundle (rule source + helper deps + refs),
  paste-able anywhere; the M2 MCP `explain_rule` payload.
- **Tests** — GCP-flavored fixture policy repo + plan fixtures; 27-path
  engine suite; CLI end-to-end suite; race-clean.
- **Release pipeline** — tag-triggered GitHub Actions matrix
  (darwin/linux × amd64/arm64) publishing to GitHub Releases.
