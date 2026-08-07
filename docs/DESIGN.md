# Design: regoxplain — grounded Rego policy comprehension for Terraform gates

Origin: designed and reviewed 2026-08-06 (office-hours -> eng review -> pre-landing review).

## Problem Statement

At work, Terraform changes in PRs are gated by OPA policies written in Rego, spread across folders of a single policy repo. Reading, comprehending, verifying, and coverage-checking these policies is hard: `opa parse` produces an AST that is machine-perfect but human-unreadable, and there is no tool that answers "explain this policy," "is scenario X covered?", or "can this be simplified?" against an existing policy repo. The user hand-reads Rego during PR reviews today.

This is a personal tool. The user is the first and only user for the foreseeable future. Monetization is explicitly out of scope.

## What Makes This Cool

The AI-for-Rego ecosystem all points the other way (natural language → generated Rego: Prose2Policy, ARPaCCino). The reverse direction — existing Rego → explanation and queryable coverage — is unserved. And because the OPA project itself documents that LLMs hallucinate Rego more than other languages (opa issue #8426), the design that wins is:

**AI as the narrator over a deterministic Rego evidence engine.** The LLM never decides. Every coverage claim is backed by an AST-index lookup or an actual policy evaluation against a Terraform plan JSON. Answers come with a provenance label: `verified-by-eval`, `backed-by-AST`, or `unverified LLM opinion`. It's a policy MRI: point it at the repo and a plan, ask "does this plan's public GCS bucket get denied?", get a dossier with matching rules, file:line citations, eval results, and a verdict. (Universal questions — "can this repo *ever* allow a public bucket?" — are capped at `probably covered` until Milestone 4's counterexample work; eval proves behavior on a given plan, not on all possible plans.)

## Constraints

- Policies are company IP. Nothing leaves the machine except through channels that are already approved (work Copilot, an approved gateway) or explicitly configured by the user.
- LLM access is uncertain: company uses GitHub Copilot; an OpenAI-format API key may be obtainable but is not guaranteed. The tool must be useful with NO LLM configured.
- Must be testable at work: terminal-friendly, no installer, no macOS app signing/notarization dependency.
- macOS dev machine; Xcode present but Swift app deprioritized (signing uncertainty).
- OPA not yet installed locally (`brew install opa` — needed only for CLI cross-checks; the engine embeds OPA as a Go library).

## Premises (agreed 2026-08-06)

1. The problem is comprehension and verification of an existing policy repo — not authoring new policies.
2. Grounded answers only: any coverage/verification claim must be backed by AST-index lookup or `opa eval` execution against a plan JSON; otherwise it is labeled "unverified — LLM opinion only."
3. Headless Go engine embedding OPA as a library (no shelling out), interfaces separate. *(Revised at approval:)* the first real interface is **MCP via Copilot chat** (stdio transport — Copilot launches the binary as a subprocess, no daemon); a minimal CLI serves as the dev/test harness; TUI and Swift are optional futures, not on the critical path.
4. LLM pluggable via OpenAI wire format (configurable base URL + key): work gateway, a Copilot-derived key (only if the workplace's terms permit it — verify before use), or local Ollama. These are three configurable endpoint options, not an automatic failover chain. Optional, not required.
5. Distribution: single static Go binary from a GitHub repo. No installer, no signing.

Note on the OPA CLI: `brew install opa` is for exploration only (`opa inspect` during scoping). The engine embeds OPA as a Go library; the CLI is never a runtime dependency.

## Cross-Model Perspective

Codex (gpt-5.5, read-only cold read of the session summary) independently converged on the same thesis and added:

- Coolest version: a "policy MRI" — grounded dossier per question: matching rules with exact locations, rule dependency graph, `input.resource_changes[*]` paths each policy touches, eval results, verdict tiers ("covered / probably covered / not proven"), and a **minimal counterexample plan JSON when it finds a gap**.
- Key insight it flagged: the interface is separable from the engine — this project is a durable engine with swappable frontends, not a UI.
- 50% reuse: OPA itself via `github.com/open-policy-agent/opa/v1/rego` (parser/compiler/evaluator, Go embedding). Regal as secondary reference for diagnostics ideas, not a dependency.
- Weekend build: `index` → `ask` (no LLM, keyword/ref matching) → `eval --plan` → minimal TUI. "LLM comes after the evidence pipeline works."
- No premise challenged; all five survived a hostile read.

## Approaches Considered

### Approach A: Single binary, engine as a clean internal package (CHOSEN as the foundation)
One Go binary: `index`, `ask`, `eval` subcommands. Engine in `internal/engine/` behind an interface so the MCP wrapper is a thin add-on, not a rewrite. Effort S-M, risk low. Fastest to a grounded answer on the real repo; no API key needed for the core. *(Revised at approval: the Bubble Tea TUI originally attached to this approach was dropped — the CLI is a dev/test harness, and MCP/Copilot is the user-facing interface.)*

### Approach B: Headless daemon + thin clients
`regoxplaind` with a localhost JSON API; TUI and future Swift app as thin clients. Matches the user's original multi-frontend instinct but pays API/process plumbing tax before answering a single real policy question. Effort L, risk medium. Deferred — becomes a refactor of A when a second frontend is real.

### Approach C: MCP evidence server (PROMOTED at approval — Milestone 2, the primary interface)
Engine tools (`search_policies`, `explain_rule`, `eval_against_plan`, `coverage_report`) exposed via MCP over stdio; Copilot/Claude Code/Codex become the chat interface — no API key ever needed, frontier-quality narration through already-approved channels, and the MCP host has natural access to the current repo/root folder. Effort M, risk low-medium. The user chose this over a TUI explicitly: no UX to build, and it plugs into the Copilot chat they already use at work. Sequenced after the engine core (A) so the tools have something deterministic to expose.

## Recommended Approach

**Engine first (A's core), MCP as the fast follower and primary interface (C). B only if/when a Swift frontend ever becomes real. TUI dropped at approval.**

**Answer model (applies to every command):** every answer carries two orthogonal dimensions — a **verdict tier** (`covered` / `probably covered` / `not proven`) and per-claim **evidence labels** (`verified-by-eval` / `backed-by-AST` / `unverified LLM opinion`). A **claim** is one line of the answer asserting one fact about one rule (see the mock output below). Answers mix evidence labels freely across claims. **Verdict aggregation:** the verdict is computed over **directly-matched rules only** — helper rules and absence notes are informational and never move the verdict. Max semantics: if any directly-matched rule contributes `covered`, the answer is `covered`; else if any contributes `probably covered`, the answer is `probably covered`; else `not proven`. The empty result is first-class: when nothing matches, the tool says "no rule references these paths — not proven covered," never "not covered" (absence of evidence is not evidence of absence).

**Eval-outcome → verdict mapping** (the semantic core):

| Eval outcome on the supplied plan | Verdict contribution |
|---|---|
| Matched rule fires (deny/violation produced) | `covered`, `verified-by-eval` |
| Matched `warn` rule fires | `probably covered` with a `warn-only` annotation (revised in code review D1: a warn detects but does not block, and the verdict tier itself must carry that — annotation alone misleads consumers reading only the top line), `verified-by-eval` |
| Matched rule evaluates, produces nothing, and the plan **contains** a resource of the queried type | `not proven (inconclusive)`, `verified-by-eval` — the tool cannot distinguish a compliant resource from an uncaught risky one on this plan; affirmative gap-flagging is reserved for Milestone 4's mutation testing, which is exactly the mechanism that can prove a gap |
| Matched rule evaluates but the plan **lacks** any resource of the queried type | stays `probably covered`, `backed-by-AST`, with note "plan has no <type> resource — eval not probative" |
| Rule matched by AST only, no plan supplied | `probably covered`, `backed-by-AST` |

**Implementation note (rule-body attribution — tightened in eng review D8):** conftest-style packages define many `deny` bodies across files; evaluating `data.pkg.deny` returns an unattributed union. Binding "fired" to a file:line claim uses **OPA's Explain/tracer events only**, joined back to the index (the "evaluate each body in isolation" alternative is deleted — isolation changes semantics: package scope, `with`, defaults). **Relevance rule:** `covered [verified-by-eval]` requires that the *specific body that fired* is one whose refs matched the question — a deny firing for an unrelated reason (e.g. a firewall violation on a bucket question) does not count for this question. When the tracer cannot attribute unambiguously (exotic constructs: `else` chains, comprehensions, negation), the tool degrades honestly: package-level claim, verdict capped at `probably covered`, with the reason stated. This is a Milestone 1 task, not an afterthought — the claim format is the product's core output.

**Mock `ask` output** (defines the claim structure; GCP is the fixture/reference cloud per eng review):

```
$ regoxplain ask "is a public GCS bucket denied?" --plan fixtures/pr-1423.json
Verdict: covered  [verified-by-eval]
  1. storage/deny_public_bucket.rego:14  deny — refs ...change.after.members ("allUsers")   [verified-by-eval: fired on plan]
  2. storage/helpers.rego:8  bucket_is_public — helper reached via deny (indirect)          [backed-by-AST]
  3. No rule references google_storage_bucket public_access_prevention                      [backed-by-AST: absence — potential gap]
```

Milestone 1 — evidence engine, CLI output only (no LLM required):
- `regoxplain index [--repo <path>]` (default: cwd) — load all `.rego` with the OPA Go library, extract packages, rules, imports, comments/metadata annotations, `input.*` / `data.*` refs, rule dependency edges, file:line locations → the index. **Index location:** `~/.cache/regoxplain/<repo-path-hash>/index.json`, never inside the policy repo itself (the company checkout stays clean; nothing to gitignore). `ask`/`eval` accept the same `--repo` flag with the same cwd default and locate the index from it. **Two-layer tolerance (tightened in eng review D10):** *parsing* is per-file tolerant — files that fail to parse are recorded in an `errors` section with diagnostics, indexing never aborts. *Compilation* is a whole-module-set stage (Rego compiles as a set, not per file — some errors only surface when modules compile together); set-level compile errors are captured too. `search`/`explain` work on a broken repo with a visible banner naming what's broken (exploration stays forgiving). **`eval` requires a clean compile of the full set and refuses otherwise** — CI would reject the broken repo, so verdicts must describe the same policy universe CI enforces, never a partial one. **Idempotent** means: running `index` twice on an unchanged repo yields byte-identical `index.json` (implementation note: serialize with sorted keys — Go map iteration is randomized); running after repo changes fully replaces the index. **State model (revised in eng review):** the **in-memory engine is the source of truth** — it loads and compiles policies itself, holds the index in memory, and refreshes when per-file content hashes mismatch. `index.json` is a versioned warm-start cache with an internal (non-contract) format: regenerated wholesale on version or hash mismatch, no schema-compat ceremony. The public contract is the engine's Go API and, in M2, the MCP tool schemas. The long-running MCP server hash-checks per tool call in process and rebuilds in memory — no file write races between concurrent tool calls. CLI commands auto-index when no cache exists (an explicit `index` run is a warm-start optimization, never a prerequisite). Config (input_mode per repo, and later LLM endpoint) lives in one place: `~/.config/regoxplain/config.toml` with per-repo tables keyed by repo path.
- **Ref extraction is best-effort by design.** Rego repos hide resource logic behind helper rules, `walk()`, and comprehensions, so static extraction will miss indirect touches. v1 mitigations: refs are attributed through **one level** of rule dependency, resolved **across package boundaries via imports** (shared `data.lib.*` helper packages are the dominant pattern in real OPA repos, so intra-package-only propagation would find near-zero indirect refs there); if `deny` calls `lib.bucket_is_public`, the helper's refs count for `deny`, labeled `indirect`. Anything deeper than one level is out of scope for v1 and is exactly why the empty/no-match answer must stay honest.
- `regoxplain search [terms...] [--resource <type>] [--attr <names>] [--plan tfplan.json]` — **structured-first search** (revised in eng review): exact and case-insensitive substring matching of supplied terms against indexed `input.*` refs, rule names, and package names. Fully deterministic — no synonym table. Rank candidates by ref-match count (direct matches above `indirect` ones). Misses surface as "no AST evidence for: <terms>." When `--plan` is supplied, matched rules are additionally evaluated against the plan and the verdict upgraded per the mapping table.
- `regoxplain ask "<question>" [--plan ...]` — free-text entry point backed by a **repo-derived vocabulary** (revised in eng review D7, accepting the outside voice — free text must work pre-MCP without requiring memorized resource names): at index time the engine auto-generates a vocabulary from the repo itself (resource types seen in refs, attribute names, rule/helper names), merged with a user-growable aliases table in `config.toml` (your own vague words → repo terms, added as you discover them). Question tokens expand through this vocabulary, then hit the same deterministic `search`. No global hardcoded synonym table — the map regenerates from the repo on every reindex, so it cannot rot. In M2, Copilot's model does richer question→term mapping natively for vague questions.
- **Input adapter (added in eng review):** the evaluator never consumes the plan file directly — it goes through an adapter configured per-repo with `input_mode`: `raw` (default; whole `terraform show -json` document as `input`, conftest convention), `wrapped:<key>` (the FILE contains an envelope; unwrap for input), `envelope:<key>` (the FILE is a raw plan; wrap it so policies reading `input.<key>.*` — e.g. `import input.plan as tfplan` — see it; discovered from the first real policy file), or `per-resource` (iterate `resource_changes`, one eval per resource). The captured CI invocation from Next Steps #1 sets this value; eval fixtures cover all three modes so the real repo's mode is guaranteed handleable. **The adapter also validates before any eval runs** (added in eng review): non-JSON input (e.g. a binary `terraform plan -out` file — error suggests `terraform show -json plan.out > plan.json`), JSON that lacks terraform-plan structure (`format_version` + `resource_changes`), and unrecognized plan schema versions each fail loudly with a specific message. Garbage input must never surface as a soft "eval not probative" verdict.
- `regoxplain eval --plan tfplan.json [--query data.<pkg>] [--data <dir>]` — evaluate policies (through the input adapter) against a real `terraform show -json` plan. **Default entrypoints (no `--query`):** every `deny` / `violation` / `warn` rule discovered by the indexer across all packages, following the conftest convention; `--query` narrows to one package or rule. **External data (tightened in eng review D9):** `--data` loads data documents (exemption lists, org config). If matched rules reference `data.*` paths that remain unsupplied, **eval refuses to run by default** — missing evaluation environment can invert rule behavior ("deny unless exempted" flips without the exemption list), so it is invalid input, not a weaker answer. The error names the exact missing paths and the `--data` fix. `--allow-missing-data` explicitly restores the exploratory behavior: eval runs, verdict capped at `probably covered`, missing paths loudly annotated.

Milestone 2 (SHIPPED v0.2.0) — **MCP server, the primary interface** (fast follower; no API key needed anywhere):
- `regoxplain mcp` — stdio-transport MCP server (Copilot launches it as a subprocess; JSON-RPC over stdin/stdout; no port, no daemon, no process management), built on the official `modelcontextprotocol/go-sdk` (stdio is its core transport; the community mark3labs/mcp-go adds HTTP/SSE this design deliberately avoids). Tools: `search_policies`, `explain_rule`, `eval_against_plan` — each mapping 1:1 onto the M1 engine API (`coverage_report` joins this list when Milestone 4 builds coverage reporting). Each tool returns the engine's deterministic output — claims with verdict tiers and evidence labels — and **the MCP host's model (Copilot) is the narrator**. No LLM client exists in regoxplain on the critical path; the narration LLM is whatever chat the user is already in.
- `explain_rule` (core requirement, elevated at approval): given a rule path (e.g. `data.s3.deny`) or a `.rego` file, assemble a **grounded context bundle**: the rule's source, its related files resolved from the index (imports and one-level helper dependencies, cross-package), metadata/annotations, its extracted refs, and — when a plan is supplied — eval evidence. The bundle is what the host model narrates from, so explanations cite real file:line locations instead of hallucinating.
- `regoxplain explain <rule-path|file>` also exists as a CLI subcommand with **no LLM required**: it prints the same context bundle as readable text (source + related files + evidence). Useful standalone, and paste-able into any chat when MCP isn't available — this is also the no-MCP fallback if work restricts local MCP servers.

Milestone 3 (SHIPPED v0.3.0 — REVISED): **the TUI**, promoted from "optional future" because work's org policy blocked MCP in Copilot and the terminal is the one interface a workplace cannot disable (the "if ever actually missed" revisit trigger fired). Live AST search + explain bundles + explicit ctrl+e evaluation; pure frontend over the engine API.

Milestone 3.5 (optional) — direct narration, only if wanted later:
- OpenAI-format LLM client (`~/.config/regoxplain/config.toml`: `base_url`, `api_key_env`, `model`, env-overridable) so CLI `explain` can produce prose itself, labeled `unverified LLM opinion`. Conditional on an API key materializing (gateway, or Copilot-derived if terms permit) or local Ollama. A TUI would slot here too if ever actually missed — currently dropped.

Milestone 4 (stretch) — verification deepening:
- Coverage report across the whole repo (which resource types/actions have no rule touching them).
- Counterexample discovery: find a plan that should be denied but isn't. **Expected to be hard** — scoped to mutation of real plan fixtures (flip one field, re-eval, diff verdicts), explicitly NOT symbolic synthesis from Rego semantics, which is research-grade.

## Testing Strategy (added in eng review)

The work policy repo is company IP and can never become test data. All testing runs against synthetic fixtures:

- **`testdata/policies/`** — a small fixture policy repo, **GCP-flavored** (per eng review — GCP is the test cloud): 2-3 rule files with `deny`/`warn` rules over `google_storage_bucket` (public IAM members / `allUsers`), `google_project_iam_member` (privilege escalation), and `google_compute_firewall` (0.0.0.0/0 ingress); one shared helper package (`data.lib.*`, exercising cross-package indirect refs); one file with rich `# METADATA` annotations; one deliberately unparseable file (exercises tolerant indexing).
- **`testdata/plans/`** — three GCP `terraform show -json` fixtures: `violating.json` (public bucket binding + open firewall — triggers denies), `compliant.json` (same resource types, compliant config — exercises the `inconclusive` row), `unrelated.json` (no matching resource types — exercises "eval not probative"). Plus `wrapped.json` and a per-resource variant for the input adapter, and two invalid inputs (binary bytes, non-plan JSON).
- **Fixture fidelity (eng review D11):** after Next Steps #1's `opa inspect` run, fixtures are shaped to mirror the work repo's real *idioms* (its helper-package style, metadata conventions, rule shapes) — patterns only, never company content.
- **Table-driven `go test`** covering all 27 enumerated paths from the eng-review coverage diagram: indexer (5), search (4), input adapter (5 incl. validation), evaluator + verdict aggregation (7), state/cache (2), and the explain bundle (2). One `-race` test for concurrent MCP staleness checks (M2).
- **Golden-file tests** pin the CLI claim/verdict output format (the same rendering the MCP tools reuse).
- **E2E:** CLI-level tests run the real binary against the fixtures (6 flows: covered verdict, honest miss, stale-repo refresh, explain bundle, wrong-file errors, unknown-rule error). M2 adds in-process MCP client tests via the official SDK.
- **Definition of done for M1:** all fixture-reachable paths tested; `make test` green; no verdict-semantics code lands without its table row.

## Open Questions

- Does the work environment permit local MCP servers in Copilot/IDE? **Now load-bearing** (MCP is the primary interface, Milestone 2) — verify early, ideally before finishing Milestone 1. Fallback if restricted: the CLI `explain` context bundle, paste-able into any chat.
- Can the user obtain an OpenAI-format API key at work (gateway, or Copilot-derived if terms permit)? Affects the optional Milestone 3 only; nothing on the critical path needs a key.
- Scale of the real policy repo (file count, packages, use of `data` documents/external data) — affects index performance targets; unknown until first run.
- Are sanitized `terraform show -json` plan fixtures available for eval tests, or do fixtures need to be synthesized?
- Which OPA version does the work repo target? Engine should pin a compatible `open-policy-agent/opa` library version — and this is bigger than a version number (eng review D11): Rego v0 vs v1 syntax (`import rego.v1`), future keywords, capabilities, and builtins all affect parse/eval. Capture the CI OPA version alongside the invocation in Next Steps #1.
- **How exactly does work CI invoke OPA?** Input document shape (whole `terraform show -json` plan as `input`, per-resource iteration, or a wrapped envelope like `{"plan": ...}`), query/entrypoint convention, any preprocessing. This is the most likely way Milestone 1 fails on the real repo: if CI reshapes the input, `eval --plan` would feed the wrong shape and every rule would silently evaluate to nothing, masquerading as "not proven." Capture the actual CI invocation during Next Steps #1.

## Success Criteria

- On the real work policy repo: `regoxplain ask "<question>" --plan tfplan.json` answers one real coverage question with named rules, file:line evidence, and a `covered` verdict backed by `verified-by-eval` evidence — end to end in under a minute.
- `regoxplain index` indexes the full repo, reporting (not dying on) unparseable files, and re-indexing an unchanged repo is byte-identical.
- Every answer (CLI and MCP) carries a verdict tier and evidence label; no unlabeled LLM claims anywhere.
- In Copilot chat via MCP: "explain `<rule>`" produces an explanation grounded in the `explain_rule` bundle, citing real file:line locations; "is X covered?" routes through `eval_against_plan` and reports the engine's verdict, not the model's guess.
- The user reaches for regoxplain instead of hand-reading Rego during at least one real PR review week.
- **CI parity (added in eng review D11 — the trust anchor):** given the same plan and data as a real PR gate run, `regoxplain eval` reproduces CI's pass/fail outcome. Verified against at least 2 captured CI triples (plan + data + outcome) from work. A parity failure names its own cause — input shape, missing data, or version skew — and if it reveals CI preprocessing (jq pipelines, bundles), the input adapter grows a mode to match; parity testing is how such modes are discovered.

## Distribution Plan

Personal tool: private GitHub repo, built locally via Makefile (`make build`, `make test`, `make index`), installed with `go install` or copied as a single static binary. **Release pipeline in M1 scope (eng review D12):** a GitHub Actions workflow builds on version tags — goreleaser (or a plain build matrix) producing darwin/linux × amd64/arm64 static binaries, published to GitHub Releases. Sharing the tool is a link from day one. No app store, no signing, no installer.

## Next Steps

1. `brew install opa` and clone the work policy repo locally; run `opa inspect` over it to learn its real scale and structure (file count, packages, annotations in use). **Also capture the CI invocation**: the exact `opa eval`/`conftest` command, input document shape, and query used in the PR gate — this defines the input contract `eval --plan` must reproduce.
2. Grab one sanitized `terraform show -json` plan output from a real PR to use as the first eval fixture.
3. Scaffold the Go module: `go mod init`, `internal/engine/` (indexer, search, input adapter, evaluator, bundle), `cmd/regoxplain/`, Makefile with build/test/index targets, and `.github/workflows/release.yml` (tag-triggered, goreleaser or build matrix).
4. Build `index` + `ask` (no LLM) and run them against the real repo — first grounded answer.
5. Add `eval --plan` with the fixture from step 2 — first `verified-by-eval` verdict. That completes Milestone 1.
6. In parallel with 3–5: confirm the work Copilot/IDE setup allows registering a local stdio MCP server (this decides whether Milestone 2 lands as designed or the CLI bundle is the interim interface).
7. Build `regoxplain mcp` (Milestone 2), register it in Copilot, and ask it to explain one real policy file — the tool's first end-to-end conversational answer.

## NOT in Scope (eng review, 2026-08-06)

- **TUI** — dropped at design approval; MCP/Copilot is the interface, CLI is the harness. Revisit only if genuinely missed.
- **Direct LLM client (M3)** — conditional on an API key materializing; nothing on the critical path needs it.
- **Swift/macOS app** — original idea, deferred indefinitely; the engine boundary keeps it possible.
- **Counterexample/mutation gap-proving (M4)** — stretch; scoped to fixture mutation, never symbolic synthesis.
- **Global synonym dictionary** — replaced by repo-derived vocabulary (D7); no hand-curated global table, ever.
- **index.json as a public contract** — demoted to internal cache (D4/2A); the contract is the engine API + MCP schemas.
- **Deeper-than-one-level ref propagation** — out for v1; the honest empty answer covers what it misses.

## What Already Exists (eng review, 2026-08-06)

- **OPA as a Go library** (`github.com/open-policy-agent/opa/v1/rego`): parser, module-set compiler, evaluator, prepared queries, tracer/Explain — the plan reuses all of it, builds none of it.
- **Official MCP Go SDK** (`modelcontextprotocol/go-sdk`): stdio transport, typed tool handlers, schema generation — M2 is a thin wrapper, not protocol work.
- **`terraform show -json`**: the plan format is Terraform's own contract; regoxplain only validates and adapts it.
- **Regal**: reference for Rego diagnostics ideas — consciously not a dependency.
- Nothing in the plan rebuilds something that exists; the built parts (index, evidence model, verdict semantics, bundles) are exactly the unserved product.
