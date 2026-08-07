# regoxplain

Grounded Rego policy comprehension for terraform gates. Point it at a repo of
OPA/Rego policies (the kind that gate `terraform plan` changes in PRs) and ask
what's covered — every answer is backed by AST evidence or a real policy
evaluation, never by an LLM's guess.

**The thesis:** LLMs hallucinate Rego more than other languages. So the engine
decides and the LLM narrates. Every claim carries a verdict tier
(`covered` / `probably covered` / `not proven`) and an evidence label
(`verified-by-eval` / `backed-by-AST`).

## Usage

```
# What touches storage buckets?
regoxplain search --repo ~/policies --resource google_storage_bucket

# Is this PR's public bucket caught? (evaluates for real)
regoxplain search --repo ~/policies --resource google_storage_bucket_iam_member \
  --plan plan.json

# Free text — expands through a vocabulary derived from YOUR repo
regoxplain ask --repo ~/policies "is a public bucket denied?"

# Run every deny/violation/warn rule against a plan
regoxplain eval --repo ~/policies --plan plan.json --data ./data

# Grounded context pack for a rule: source + helpers + refs (paste anywhere)
regoxplain explain --repo ~/policies data.terraform.storage.deny
```

`plan.json` is `terraform show -json` output (the binary planfile is detected
and rejected with the fix). If CI wraps the input or iterates per resource,
set `input_mode` in `~/.config/regoxplain/config.toml`:

```toml
[repos."/abs/path/to/policies"]
input_mode = "raw"          # or envelope:<key> / wrapped:<key> / per-resource
# envelope:plan — for policies that read input.plan.* (e.g.
#   `import input.plan as tfplan`): a standard plan file is wrapped
#   under the key before evaluation. Also available per-invocation:
#   --input-mode envelope:plan

[aliases]                    # your own vague words -> repo terms
public = ["allUsers", "public_access_prevention"]
```

## Honesty rules (the point of the tool)

- `covered` requires the **specific rule body you asked about** to have fired
  (tracer-attributed) — a deny firing for an unrelated reason doesn't count.
- A rule that evaluated but didn't fire on a plan **containing** its resource
  type is `not proven (inconclusive)` — compliant config and coverage gap are
  indistinguishable on that plan, and the tool says so.
- Missing external data (`data.exemptions.*`) is a **hard error**, not a
  softer verdict — absent exemption lists can invert rule behavior
  (`--allow-missing-data` to override, verdict capped).
- Eval requires the whole policy set to compile, exactly like CI. Search and
  explain keep working on a broken repo, with a banner.
- Empty results say "no AST evidence", never "not covered".

## Development

```
make test    # full suite against GCP-flavored fixtures in testdata/
make demo    # end-to-end: violating plan -> covered verdict
```

## TUI (works anywhere a terminal works)

```
regoxplain tui --repo /path/to/policies --plan plan.json --input-mode envelope:plan
```

Type to search (free text, repo-derived vocabulary), ↑/↓ to browse matches
with each rule's grounded bundle in the evidence pane, **ctrl+e** to evaluate
against the plan — the verdict bar upgrades from `backed-by-AST only` to
`verified-by-eval`. Built for environments where MCP is policy-blocked:
if you have a terminal, you have the tool.

## MCP server (use it from Copilot / Claude)

`regoxplain mcp` exposes the engine as MCP tools over stdio —
`search_policies`, `explain_rule`, `eval_against_plan` — so the chat you
already use becomes the interface. The model narrates; the engine's verdicts
and evidence labels stay authoritative.

**VS Code / GitHub Copilot** — add `.vscode/mcp.json` in the policy repo
(or your user config):

```json
{
  "servers": {
    "regoxplain": {
      "type": "stdio",
      "command": "regoxplain",
      "args": ["mcp", "--repo", "${workspaceFolder}"]
    }
  }
}
```

Then in Copilot Chat (Agent mode): *"Is a public GCS bucket denied by our
policies? Check against plan.json"* — Copilot calls the tools and cites the
engine's file:line claims.

**Claude Code:**

```bash
claude mcp add regoxplain -- regoxplain mcp --repo .
```

The binary must be on `PATH` (`make build` then copy `bin/regoxplain`, or
`go install github.com/yorozuko/regoxplain/cmd/regoxplain@latest`).

The full design — answer model, verdict semantics, milestones, and every
reviewed decision — lives in [docs/DESIGN.md](docs/DESIGN.md).
