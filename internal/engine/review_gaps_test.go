package engine

// Tests added by the pre-landing review (D4): the six coverage gaps the
// testing specialist identified, plus regression pins for review fixes.

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Gap 1: staleness on in-place modification and deletion (the common cases —
// the original test only covered file addition).
func TestEngineStaleOnModifiedAndDeletedFile(t *testing.T) {
	t.Setenv("REGOXPLAIN_CACHE_DIR", t.TempDir())
	repo := copyFixtureRepo(t)
	eng := New(repo)
	ix1, err := eng.Ensure()
	if err != nil {
		t.Fatal(err)
	}
	n := len(ix1.Rules)
	rel := filepath.Join("storage", "deny_public_bucket.rego")
	p := filepath.Join(repo, rel)

	data, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, append(data, []byte("\n# touched\n")...), 0o644); err != nil {
		t.Fatal(err)
	}
	ix2, err := eng.Ensure()
	if err != nil {
		t.Fatal(err)
	}
	if ix2.FileHashes[rel] == ix1.FileHashes[rel] {
		t.Fatal("modified file must trigger rebuild with a new hash")
	}

	if err := os.Remove(p); err != nil {
		t.Fatal(err)
	}
	ix3, err := eng.Ensure()
	if err != nil {
		t.Fatal(err)
	}
	if len(ix3.Rules) >= n {
		t.Fatalf("deleted file's rules must vanish: %d >= %d", len(ix3.Rules), n)
	}
}

// Gap 2: config loading — valid with alias normalization and per-repo mode
// lookup (trailing slash), absent file defaults, malformed hard error.
func configSandbox(t *testing.T) string {
	t.Helper()
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)
	t.Setenv("XDG_CONFIG_HOME", tmp)
	dir, err := os.UserConfigDir()
	if err != nil {
		t.Skip("no user config dir on this platform")
	}
	cfgDir := filepath.Join(dir, "regoxplain")
	if err := os.MkdirAll(cfgDir, 0o755); err != nil {
		t.Fatal(err)
	}
	return filepath.Join(cfgDir, "config.toml")
}

func TestLoadConfigValid(t *testing.T) {
	cfgPath := configSandbox(t)
	repo := t.TempDir()
	content := "[aliases]\nPublic = [\"allUsers\"]\n\n[repos.\"" + repo + "/\"]\ninput_mode = \"per-resource\"\n"
	if err := os.WriteFile(cfgPath, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadConfig()
	if err != nil {
		t.Fatal(err)
	}
	// Alias keys normalize through the tokenizer: "Public" must match the
	// lowercase question token "public".
	if got := cfg.Aliases["public"]; len(got) == 0 || got[0] != "allUsers" {
		t.Fatalf("alias key must normalize to lowercase token, got %v", cfg.Aliases)
	}
	// Trailing slash in the config key must still match the repo path.
	if mode := cfg.InputModeFor(repo); mode != "per-resource" {
		t.Fatalf("InputModeFor with trailing-slash key = %q, want per-resource", mode)
	}
	if mode := cfg.InputModeFor(t.TempDir()); mode != "raw" {
		t.Fatalf("unknown repo must default to raw, got %q", mode)
	}
}

func TestLoadConfigAbsentAndMalformed(t *testing.T) {
	cfgPath := configSandbox(t)

	cfg, err := LoadConfig() // no file yet
	if err != nil || cfg == nil || cfg.Aliases == nil || cfg.Repos == nil {
		t.Fatalf("absent config must yield initialized defaults, got %v / %v", cfg, err)
	}

	if err := os.WriteFile(cfgPath, []byte("aliases = not toml ["), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfig(); err == nil {
		t.Fatal("malformed config must be a hard error, not silent defaults — silent fallback makes input_mode quietly wrong")
	}
}

// Gap 3: adapter negative paths — empty wrapped key, non-object wrapped key,
// empty per-resource list, resource_changes not a list.
func TestAdapterNegativePaths(t *testing.T) {
	if _, _, err := LoadPlan(planPath(t, "wrapped.json"), "wrapped:"); err == nil || !strings.Contains(err.Error(), "requires a key") {
		t.Fatalf("bare wrapped: must fail with named reason, got %v", err)
	}
	if _, _, err := LoadPlan(planPath(t, "violating.json"), "wrapped:format_version"); err == nil || !strings.Contains(err.Error(), "no object at key") {
		t.Fatalf("wrapped over a non-object key must fail, got %v", err)
	}

	dir := t.TempDir()
	empty := filepath.Join(dir, "empty.json")
	if err := os.WriteFile(empty, []byte(`{"format_version":"1.2","resource_changes":[]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := LoadPlan(empty, "per-resource"); err == nil || !strings.Contains(err.Error(), "empty resource_changes") {
		t.Fatalf("per-resource on empty list must fail, got %v", err)
	}

	notList := filepath.Join(dir, "notlist.json")
	if err := os.WriteFile(notList, []byte(`{"format_version":"1.2","resource_changes":{}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := LoadPlan(notList, "raw"); err == nil || !strings.Contains(err.Error(), "not a list") {
		t.Fatalf("resource_changes as object must fail loudly, got %v", err)
	}
}

// Gap 4: per-resource mode end-to-end — FiredLabel carries the resource
// address and the rendered claim shows it.
func TestEvalPerResourceMode(t *testing.T) {
	ix, err := BuildIndex(filepath.Join("..", "..", "testdata", "rc-policies"))
	if err != nil {
		t.Fatal(err)
	}
	evals, types, err := Evaluate(context.Background(), ix, nil, EvalOptions{
		PlanPath:  planPath(t, "violating.json"),
		InputMode: "per-resource",
	})
	if err != nil {
		t.Fatal(err)
	}
	deny := evals["data.terraform.rc.deny"]
	if deny == nil || !deny.Fired {
		t.Fatalf("rc deny should fire in per-resource mode: %+v", deny)
	}
	if !strings.Contains(deny.FiredLabel, "google_compute_firewall.allow_all") {
		t.Fatalf("FiredLabel should carry the resource address, got %q", deny.FiredLabel)
	}
	ms := Search(ix, SearchParams{Resources: []string{"google_compute_firewall"}})
	ans := BuildAnswer(ix, ms, evals, types, nil)
	found := false
	for _, c := range ans.Claims {
		if strings.Contains(c.Text, "on google_compute_firewall.allow_all") {
			found = true
		}
	}
	if !found {
		t.Fatalf("claim should name the firing resource: %+v", ans.Claims)
	}
}

// Gap 5: cache negative paths — version mismatch and corrupt JSON are both
// discarded (nil), and Ensure still produces a correct index.
func TestLoadCacheNegatives(t *testing.T) {
	t.Setenv("REGOXPLAIN_CACHE_DIR", t.TempDir())
	repo := copyFixtureRepo(t)
	eng := New(repo)
	ix, err := eng.Ensure()
	if err != nil {
		t.Fatal(err)
	}
	p, err := CachePath(repo)
	if err != nil {
		t.Fatal(err)
	}

	stale := *ix
	stale.Version = 0
	data, _ := json.Marshal(&stale)
	if err := os.WriteFile(p, data, 0o644); err != nil {
		t.Fatal(err)
	}
	if got := LoadCache(repo); got != nil {
		t.Fatal("version-mismatched cache must be discarded")
	}

	if err := os.WriteFile(p, []byte("{corrupt"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := LoadCache(repo); got != nil {
		t.Fatal("corrupt cache must be discarded")
	}
	ix2, err := New(repo).Ensure()
	if err != nil || len(ix2.Rules) != len(ix.Rules) {
		t.Fatalf("Ensure must rebuild past a corrupt cache: %v (%d vs %d rules)", err, len(ix2.Rules), len(ix.Rules))
	}
}

// Gap 6 + regression pin for the fired-detection fix: a complete rule
// producing a scalar value counts as fired.
func TestScalarValuedRuleFires(t *testing.T) {
	ix, err := BuildIndex(filepath.Join("..", "..", "testdata", "scalar-policies"))
	if err != nil {
		t.Fatal(err)
	}
	evals, _, err := Evaluate(context.Background(), ix, nil, EvalOptions{
		PlanPath:  planPath(t, "unrelated.json"), // contains google_pubsub_topic
		InputMode: "raw",
	})
	if err != nil {
		t.Fatal(err)
	}
	deny := evals["data.terraform.scalar.deny"]
	if deny == nil || !deny.Fired {
		t.Fatalf("scalar-valued deny must count as fired: %+v", deny)
	}
	if len(deny.Messages) == 0 || !strings.Contains(deny.Messages[0], "forbidden") {
		t.Fatalf("scalar value should surface as the message: %v", deny.Messages)
	}
}

// Regression pin for the D9 deep-walk fix: a partial data file (top-level key
// present, required subtree absent) must still hard-error.
func TestMissingDataDetectsPartialDocument(t *testing.T) {
	ix := fixtureIx(t)
	partial := t.TempDir()
	if err := os.WriteFile(filepath.Join(partial, "exemptions.json"), []byte(`{"exemptions":{}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	_, _, err := Evaluate(context.Background(), ix, nil, EvalOptions{
		PlanPath:    planPath(t, "violating.json"),
		InputMode:   "raw",
		DataDir:     partial,
		QueryPrefix: "data.terraform.iam",
	})
	var mde *MissingDataError
	if !errors.As(err, &mde) {
		t.Fatalf("partial data document (exemptions present, members absent) must be a MissingDataError, got %v", err)
	}
}

// Regression pin for the data-dir collision fix.
func TestDataDirDuplicateKeyIsError(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"a.json", "b.json"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(`{"exemptions":{"members":[]}}`), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	ix := fixtureIx(t)
	_, _, err := Evaluate(context.Background(), ix, nil, EvalOptions{
		PlanPath:    planPath(t, "violating.json"),
		InputMode:   "raw",
		DataDir:     dir,
		QueryPrefix: "data.terraform.iam",
	})
	if err == nil || !strings.Contains(err.Error(), "--data conflict") {
		t.Fatalf("duplicate top-level data keys must fail loudly, got %v", err)
	}
}

// Envelope input mode (real-world discovery: policies importing input.plan):
// a standard plan file must be wrapped under the key, or every rule silently
// evaluates against undefined — the trap, and the fix, both pinned here.
func TestEnvelopeInputMode(t *testing.T) {
	ix, err := BuildIndex(filepath.Join("..", "..", "testdata", "envelope-policies"))
	if err != nil {
		t.Fatal(err)
	}
	// The trap: raw mode on an input.plan-importing policy — nothing fires.
	evalsRaw, _, err := Evaluate(context.Background(), ix, nil, EvalOptions{
		PlanPath:  planPath(t, "sql-noregion.json"),
		InputMode: "raw",
	})
	if err != nil {
		t.Fatal(err)
	}
	if evalsRaw["data.terraform.envelope.deny"].Fired {
		t.Fatal("raw mode should NOT fire (input.plan undefined) — that's the trap")
	}
	// The fix: envelope:plan wraps the standard plan under input.plan.
	evals, _, err := Evaluate(context.Background(), ix, nil, EvalOptions{
		PlanPath:  planPath(t, "sql-noregion.json"),
		InputMode: "envelope:plan",
	})
	if err != nil {
		t.Fatal(err)
	}
	deny := evals["data.terraform.envelope.deny"]
	if deny == nil || !deny.Fired {
		t.Fatalf("envelope:plan must make the missing-region deny fire: %+v", deny)
	}
	if len(deny.Messages) == 0 || !strings.Contains(deny.Messages[0], "missing on google_sql_database_instance.main") {
		t.Fatalf("expected the missing-region message: %v", deny.Messages)
	}
	// Adapter negatives for the new mode.
	if _, _, err := LoadPlan(planPath(t, "sql-noregion.json"), "envelope:"); err == nil {
		t.Fatal("bare envelope: must fail with named reason")
	}
}
