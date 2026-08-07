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
input_mode = "raw"          # or "wrapped:<key>" or "per-resource"

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

Milestone 2 exposes the same engine as an MCP stdio server
(`search_policies`, `explain_rule`, `eval_against_plan`) so Copilot/Claude
narrate over grounded evidence. The full design — answer model, verdict
semantics, milestones, and every reviewed decision — lives in
[docs/DESIGN.md](docs/DESIGN.md).
