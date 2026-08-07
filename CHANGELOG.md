# Changelog

## 0.1.0 — 2026-08-06

Milestone 1: the evidence engine, per the approved design doc
([docs/DESIGN.md](docs/DESIGN.md)).

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

### Review hardening (pre-landing review, same release)

- **Security**: OPA compiled with restricted capabilities — `http.send` /
  `net.lookup*` / `opa.runtime` stripped so untrusted `.rego` cannot exfiltrate
  plan contents; evaluation bounded by `--eval-timeout` (default 30s); release
  workflow token scoped to the release job; third-party action SHA-pinned.
- **Verdict honesty**: missing-data gate walks the FULL `data.*` path (partial
  documents no longer suppress the hard error) and sees data refs through
  helper chains at any depth; scalar-valued rules count as fired; a firing
  `warn` caps at `probably covered` (detects, does not block); only the
  best-scoring match may drive `covered`; duplicate `--data` keys fail loudly;
  `--query` respects package segment boundaries.
- **Evaluator**: compiler retained from indexing (no re-parse, no stale-file
  claim race), prepared queries per entrypoint, tracing only on fired pairs,
  full-path body attribution, per-input attribution honesty.
- **Fixes**: per-file config path canonicalization (symlinks, trailing slash),
  alias key normalization, plan `resource_changes` shape validation, version
  string single-sourced from VERSION, e2e config isolation, plus 10 new tests
  pinning the review-identified gaps.
