package engine

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

var (
	fixtureOnce  sync.Once
	fixtureIndex *Index
	fixtureErr   error
)

func policiesDir(t *testing.T) string {
	t.Helper()
	return filepath.Join("..", "..", "testdata", "policies")
}

func planPath(t *testing.T, name string) string {
	t.Helper()
	return filepath.Join("..", "..", "testdata", "plans", name)
}

func fixtureIx(t *testing.T) *Index {
	t.Helper()
	fixtureOnce.Do(func() {
		fixtureIndex, fixtureErr = BuildIndex(policiesDir(t))
	})
	if fixtureErr != nil {
		t.Fatalf("BuildIndex: %v", fixtureErr)
	}
	return fixtureIndex
}

func findRule(t *testing.T, ix *Index, path string, row int) RuleInfo {
	t.Helper()
	for _, r := range ix.Rules {
		if r.Path == path && (row == 0 || r.Row == row) {
			return r
		}
	}
	t.Fatalf("rule %s (row %d) not in index", path, row)
	return RuleInfo{}
}

// --- Indexer -----------------------------------------------------------------

func TestIndexerParsesFixtureRepo(t *testing.T) {
	ix := fixtureIx(t)
	if len(ix.Errors) != 0 || len(ix.CompileErrors) != 0 {
		t.Fatalf("fixture repo should be clean, got errors=%v compile=%v", ix.Errors, ix.CompileErrors)
	}
	wantPkgs := []string{"data.lib", "data.terraform.iam", "data.terraform.network", "data.terraform.storage"}
	if len(ix.Packages) != len(wantPkgs) {
		t.Fatalf("packages = %v, want %v", ix.Packages, wantPkgs)
	}
	kinds := map[string]int{}
	for _, r := range ix.Rules {
		kinds[r.Kind]++
	}
	if kinds["deny"] < 4 {
		t.Errorf("want >=4 deny bodies, got %d", kinds["deny"])
	}
	if kinds["warn"] != 2 {
		t.Errorf("want 2 warn bodies, got %d", kinds["warn"])
	}
	if kinds["helper"] < 3 {
		t.Errorf("want >=3 helper rules, got %d", kinds["helper"])
	}
}

func TestIndexerTolerantOnBrokenFile(t *testing.T) {
	ix, err := BuildIndex(filepath.Join("..", "..", "testdata", "broken-policies"))
	if err != nil {
		t.Fatalf("tolerant indexing must not abort: %v", err)
	}
	if len(ix.Errors) != 1 || ix.Errors[0].File != "broken.rego" {
		t.Fatalf("want broken.rego recorded, got %v", ix.Errors)
	}
	if len(ix.Rules) == 0 {
		t.Fatal("good.rego rules should still be indexed")
	}
	if ix.CleanCompile() {
		t.Fatal("broken repo must not report CleanCompile")
	}
	if ix.Brokenness() == "" {
		t.Fatal("broken repo must produce a banner")
	}
}

func TestIndexerCrossPackageIndirectRefs(t *testing.T) {
	ix := fixtureIx(t)
	// network warn calls lib.any_open_firewall (no-arg helper touching
	// input.resource_changes) — the ref must propagate as indirect.
	warn := findRule(t, ix, "data.terraform.network.warn", 0)
	found := false
	for _, ref := range warn.Refs {
		if ref.Ref == "input.resource_changes" && ref.Indirect {
			found = true
		}
	}
	if !found {
		t.Fatalf("network.warn should inherit input.resource_changes indirect ref, refs=%v", warn.Refs)
	}
	if len(warn.Deps) == 0 || !strings.Contains(strings.Join(warn.Deps, ","), "data.lib.any_open_firewall") {
		t.Fatalf("network.warn deps should name the helper, got %v", warn.Deps)
	}
}

func TestIndexerLiteralsCarryResourceTypes(t *testing.T) {
	ix := fixtureIx(t)
	deny := findRule(t, ix, "data.terraform.storage.deny", 0)
	joined := strings.Join(deny.IndirectLiterals, ",")
	if !strings.Contains(joined, "google_storage_bucket_iam_member") || !strings.Contains(joined, "allUsers") {
		t.Fatalf("storage deny body 1 should inherit helper literals as indirect, got %v", deny.IndirectLiterals)
	}
	iam := findRule(t, ix, "data.terraform.iam.deny", 0)
	hasExemptions := false
	for _, ref := range iam.Refs {
		if ref.Ref == "data.exemptions.members" && ref.Indirect {
			hasExemptions = true
		}
	}
	if !hasExemptions {
		t.Fatalf("iam deny should inherit data.exemptions.members from its helper, refs=%v", iam.Refs)
	}
}

func TestIndexerDeterministicCache(t *testing.T) {
	t.Setenv("REGOXPLAIN_CACHE_DIR", t.TempDir())
	ix, err := BuildIndex(policiesDir(t))
	if err != nil {
		t.Fatal(err)
	}
	if err := ix.SaveCache(); err != nil {
		t.Fatal(err)
	}
	p, _ := CachePath(ix.RepoPath)
	first, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	ix2, err := BuildIndex(policiesDir(t))
	if err != nil {
		t.Fatal(err)
	}
	if err := ix2.SaveCache(); err != nil {
		t.Fatal(err)
	}
	second, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if string(first) != string(second) {
		t.Fatal("re-index of unchanged repo must be byte-identical")
	}
	if len(ix.FileHashes) == 0 {
		t.Fatal("index must record per-file hashes")
	}
}

// --- Engine state ------------------------------------------------------------

func copyFixtureRepo(t *testing.T) string {
	t.Helper()
	dst := t.TempDir()
	src := policiesDir(t)
	err := filepath.Walk(src, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, path)
		target := filepath.Join(dst, rel)
		if info.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return os.WriteFile(target, data, 0o644)
	})
	if err != nil {
		t.Fatal(err)
	}
	return dst
}

func TestEngineWarmStartAndStaleness(t *testing.T) {
	t.Setenv("REGOXPLAIN_CACHE_DIR", t.TempDir())
	repo := copyFixtureRepo(t)
	eng := New(repo)
	ix1, err := eng.Ensure()
	if err != nil {
		t.Fatal(err)
	}
	rules1 := len(ix1.Rules)

	// Cold engine, warm cache: loads without rebuild and matches.
	eng2 := New(repo)
	ix2, err := eng2.Ensure()
	if err != nil {
		t.Fatal(err)
	}
	if len(ix2.Rules) != rules1 {
		t.Fatalf("warm start rules = %d, want %d", len(ix2.Rules), rules1)
	}

	// Repo change: add a rule; Ensure must rebuild.
	extra := filepath.Join(repo, "extra.rego")
	err = os.WriteFile(extra, []byte("package terraform.extra\n\nimport rego.v1\n\ndeny contains msg if {\n\tsome rc in input.resource_changes\n\trc.type == \"google_bigquery_dataset\"\n\tmsg := \"no bigquery\"\n}\n"), 0o644)
	if err != nil {
		t.Fatal(err)
	}
	ix3, err := eng2.Ensure()
	if err != nil {
		t.Fatal(err)
	}
	if len(ix3.Rules) != rules1+1 {
		t.Fatalf("after repo change rules = %d, want %d", len(ix3.Rules), rules1+1)
	}
}

func TestEngineConcurrentEnsure(t *testing.T) {
	t.Setenv("REGOXPLAIN_CACHE_DIR", t.TempDir())
	repo := copyFixtureRepo(t)
	eng := New(repo)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ix, err := eng.Ensure()
			if err != nil || len(ix.Rules) == 0 {
				t.Errorf("concurrent Ensure: %v", err)
			}
			_ = Search(ix, SearchParams{Terms: []string{"bucket"}})
		}()
	}
	wg.Wait()
}

// --- Search / ask ------------------------------------------------------------

func TestSearchDirectMatchAndRanking(t *testing.T) {
	ix := fixtureIx(t)
	ms := Search(ix, SearchParams{Resources: []string{"google_storage_bucket"}})
	if len(ms) == 0 {
		t.Fatal("expected matches for google_storage_bucket")
	}
	if ms[0].Score() < ms[len(ms)-1].Score() {
		t.Fatal("matches must be ranked by score desc")
	}
	foundStorageDeny := false
	for _, m := range ms {
		if m.Rule.Package == "data.terraform.storage" && m.Rule.Kind == "deny" {
			foundStorageDeny = true
		}
	}
	if !foundStorageDeny {
		t.Fatal("storage deny should match google_storage_bucket")
	}
}

func TestSearchIndirectOnlyMatchIsLabeled(t *testing.T) {
	ix := fixtureIx(t)
	// network.warn touches input.resource_changes only indirectly.
	ms := Search(ix, SearchParams{Terms: []string{"resource_changes"}})
	var warnMatch *Match
	for i := range ms {
		if ms[i].Rule.Path == "data.terraform.network.warn" {
			warnMatch = &ms[i]
		}
	}
	if warnMatch == nil {
		t.Fatal("network.warn should match resource_changes via indirect ref")
	}
	if len(warnMatch.IndirectHit) == 0 {
		t.Fatalf("network.warn match must be labeled indirect, got direct=%v", warnMatch.DirectHits)
	}
}

func TestSearchNoMatchesIsHonest(t *testing.T) {
	ix := fixtureIx(t)
	ms := Search(ix, SearchParams{Terms: []string{"zzz_no_such_thing"}})
	if len(ms) != 0 {
		t.Fatalf("want zero matches, got %d", len(ms))
	}
	ans := BuildAnswer(ix, ms, nil, nil, nil)
	if ans.Verdict != VerdictNotProven {
		t.Fatalf("empty result verdict = %q, want %q", ans.Verdict, VerdictNotProven)
	}
	out := Render(ans, []string{"zzz"}, "")
	if !strings.Contains(out, "not proven covered") || !strings.Contains(out, "no AST evidence for: zzz") {
		t.Fatalf("render must state absence honestly:\n%s", out)
	}
}

func TestSearchResourceAndAttrFilters(t *testing.T) {
	ix := fixtureIx(t)
	ms := Search(ix, SearchParams{Resources: []string{"google_compute_firewall"}, Attrs: []string{"source_ranges"}})
	for _, m := range ms {
		if m.Rule.Package == "data.terraform.storage" {
			t.Fatalf("attr+resource filters must exclude storage rules, matched %s", m.Rule.Path)
		}
	}
	if len(ms) == 0 {
		t.Fatal("firewall rules should match resource+attr filters")
	}
}

func TestAskTokensExpandThroughVocabAndAliases(t *testing.T) {
	ix := fixtureIx(t)
	aliases := map[string][]string{"open": {"0.0.0.0/0"}}
	terms, misses := AskTokens(ix, aliases, "is a public bucket denied?")
	if len(terms) == 0 {
		t.Fatalf("expected vocabulary expansion for 'public bucket', got misses=%v", misses)
	}
	joined := strings.Join(terms, ",")
	if !strings.Contains(joined, "bucket") {
		t.Fatalf("terms should include bucket-ish tokens: %v", terms)
	}
	_, misses2 := AskTokens(ix, nil, "is the flurble covered?")
	if len(misses2) == 0 {
		t.Fatal("nonsense token must be reported as a miss")
	}
}

// --- Input adapter -----------------------------------------------------------

func TestAdapterRawMode(t *testing.T) {
	inputs, types, err := LoadPlan(planPath(t, "violating.json"), "raw")
	if err != nil {
		t.Fatal(err)
	}
	if len(inputs) != 1 || inputs[0].Label != "" {
		t.Fatalf("raw mode should yield one unlabeled input, got %+v", inputs)
	}
	if !types["google_storage_bucket"] || !types["google_compute_firewall"] {
		t.Fatalf("resource types missing: %v", types)
	}
}

func TestAdapterWrappedMode(t *testing.T) {
	inputs, types, err := LoadPlan(planPath(t, "wrapped.json"), "wrapped:plan")
	if err != nil {
		t.Fatal(err)
	}
	if len(inputs) != 1 {
		t.Fatalf("wrapped mode should yield one input, got %d", len(inputs))
	}
	if !types["google_compute_firewall"] {
		t.Fatalf("wrapped mode must see inner resource types: %v", types)
	}
	if _, _, err := LoadPlan(planPath(t, "wrapped.json"), "raw"); err == nil {
		t.Fatal("raw mode on a wrapped file must fail validation")
	}
}

func TestAdapterPerResourceMode(t *testing.T) {
	inputs, _, err := LoadPlan(planPath(t, "violating.json"), "per-resource")
	if err != nil {
		t.Fatal(err)
	}
	if len(inputs) != 4 {
		t.Fatalf("per-resource should yield 4 inputs, got %d", len(inputs))
	}
	if inputs[0].Label == "" {
		t.Fatal("per-resource inputs must carry resource addresses")
	}
}

func TestAdapterRejectsBinaryPlanfile(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "plan.out")
	if err := os.WriteFile(bin, []byte("PK\x03\x04binarybinary\x00\x00"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, _, err := LoadPlan(bin, "raw")
	if err == nil || !strings.Contains(err.Error(), "terraform show -json") {
		t.Fatalf("binary planfile must produce actionable error, got %v", err)
	}
	var ae *AdapterError
	if !errors.As(err, &ae) {
		t.Fatalf("want AdapterError, got %T", err)
	}
}

func TestAdapterRejectsNonPlanJSONAndUnknownMode(t *testing.T) {
	_, _, err := LoadPlan(planPath(t, "notaplan.json"), "raw")
	if err == nil || !strings.Contains(err.Error(), "not a terraform plan") {
		t.Fatalf("non-plan JSON must fail with a named reason, got %v", err)
	}
	_, _, err = LoadPlan(planPath(t, "violating.json"), "sideways")
	if err == nil || !strings.Contains(err.Error(), "unknown input_mode") {
		t.Fatalf("unknown mode must fail loudly, got %v", err)
	}
}

// --- Evaluator + verdict -----------------------------------------------------

func evalStorage(t *testing.T, plan string) (map[string]*EvalResult, map[string]bool) {
	t.Helper()
	ix := fixtureIx(t)
	evals, types, err := Evaluate(context.Background(), ix, EvalOptions{
		PlanPath:    planPath(t, plan),
		InputMode:   "raw",
		QueryPrefix: "data.terraform.storage",
	})
	if err != nil {
		t.Fatal(err)
	}
	return evals, types
}

func TestEvalFiresWithBodyAttribution(t *testing.T) {
	evals, _ := evalStorage(t, "violating.json")
	deny := evals["data.terraform.storage.deny"]
	if deny == nil || !deny.Fired {
		t.Fatalf("storage deny should fire on violating plan: %+v", deny)
	}
	if !deny.Attributed || len(deny.FiredBodies) == 0 {
		t.Fatalf("tracer should attribute the fired body, got %+v", deny)
	}
	ix := fixtureIx(t)
	body1 := findRule(t, ix, "data.terraform.storage.deny", 0) // first body by row
	if !bodyFired(deny, body1) {
		t.Fatalf("fired body should be body 1 (allUsers binding) at row %d, got %+v", body1.Row, deny.FiredBodies)
	}
	if len(deny.Messages) == 0 || !strings.Contains(deny.Messages[0], "public bucket IAM binding") {
		t.Fatalf("deny message missing: %v", deny.Messages)
	}
}

func TestVerdictCoveredRequiresMatchedBodyToFire(t *testing.T) {
	ix := fixtureIx(t)
	evals, types := evalStorage(t, "violating.json")

	// Search that matches body 1 (allUsers) → covered.
	ms := Search(ix, SearchParams{Terms: []string{"allUsers"}})
	ans := BuildAnswer(ix, ms, evals, types, nil)
	if ans.Verdict != VerdictCovered {
		t.Fatalf("allUsers question on violating plan: verdict = %q, want covered\nclaims: %+v", ans.Verdict, ans.Claims)
	}

	// Search that matches ONLY body 2 (public_access_prevention): body 1
	// fired, body 2 did not — the D8 relevance rule forbids covered.
	ms2 := Search(ix, SearchParams{Attrs: []string{"public_access_prevention"}})
	onlyBody2 := ms2[:0]
	for _, m := range ms2 {
		if m.Rule.Kind == "deny" {
			hasLit := false
			for _, l := range m.Rule.Literals {
				if l == "inherited" {
					hasLit = true
				}
			}
			if hasLit {
				onlyBody2 = append(onlyBody2, m)
			}
		}
	}
	if len(onlyBody2) == 0 {
		t.Fatal("expected a body-2 match for public_access_prevention")
	}
	ans2 := BuildAnswer(ix, onlyBody2, evals, types, nil)
	if ans2.Verdict == VerdictCovered {
		t.Fatalf("body 2 did not fire — verdict must not be covered, got %q\nclaims: %+v", ans2.Verdict, ans2.Claims)
	}
	foundDifferentBody := false
	for _, c := range ans2.Claims {
		if strings.Contains(c.Text, "different") {
			foundDifferentBody = true
		}
	}
	if !foundDifferentBody {
		t.Fatalf("claims should state a different body fired: %+v", ans2.Claims)
	}
}

func TestVerdictInconclusiveOnCompliantPlan(t *testing.T) {
	ix := fixtureIx(t)
	evals, types := evalStorage(t, "compliant.json")
	ms := Search(ix, SearchParams{Terms: []string{"allUsers"}})
	ans := BuildAnswer(ix, ms, evals, types, nil)
	if ans.Verdict != VerdictInconclusive {
		t.Fatalf("compliant plan with governed resources: verdict = %q, want %q\nclaims: %+v", ans.Verdict, VerdictInconclusive, ans.Claims)
	}
	for _, c := range ans.Claims {
		if strings.Contains(c.Text, "gap") && !strings.Contains(c.Text, "cannot distinguish") {
			t.Fatalf("compliant plan must never be flagged as a gap: %q", c.Text)
		}
	}
}

func TestVerdictNotProbativeOnUnrelatedPlan(t *testing.T) {
	ix := fixtureIx(t)
	evals, types := evalStorage(t, "unrelated.json")
	ms := Search(ix, SearchParams{Terms: []string{"allUsers"}})
	ans := BuildAnswer(ix, ms, evals, types, nil)
	if ans.Verdict != VerdictProbably {
		t.Fatalf("unrelated plan: verdict = %q, want %q", ans.Verdict, VerdictProbably)
	}
	found := false
	for _, c := range ans.Claims {
		if strings.Contains(c.Text, "eval not probative") {
			found = true
		}
	}
	if !found {
		t.Fatalf("claims should say eval not probative: %+v", ans.Claims)
	}
}

func TestWarnFiresAsCoveredWarnOnly(t *testing.T) {
	ix := fixtureIx(t)
	evals, types := evalStorage(t, "violating.json")
	warn := evals["data.terraform.storage.warn"]
	if warn == nil || !warn.Fired {
		t.Fatalf("storage warn should fire (uniform_bucket_level_access=false): %+v", warn)
	}
	ms := Search(ix, SearchParams{Attrs: []string{"uniform_bucket_level_access"}})
	ans := BuildAnswer(ix, ms, evals, types, nil)
	foundWarnOnly := false
	for _, c := range ans.Claims {
		if strings.Contains(c.Text, "warn-only") {
			foundWarnOnly = true
		}
	}
	if !foundWarnOnly {
		t.Fatalf("warn claim should carry warn-only annotation: %+v", ans.Claims)
	}
}

func TestMissingDataIsHardError(t *testing.T) {
	ix := fixtureIx(t)
	_, _, err := Evaluate(context.Background(), ix, EvalOptions{
		PlanPath:    planPath(t, "violating.json"),
		InputMode:   "raw",
		QueryPrefix: "data.terraform.iam",
	})
	var mde *MissingDataError
	if !errors.As(err, &mde) {
		t.Fatalf("iam eval without --data must be a MissingDataError, got %v", err)
	}
	if len(mde.Paths) == 0 || !strings.Contains(mde.Paths[0], "data.exemptions") {
		t.Fatalf("error must name the missing document: %v", mde.Paths)
	}
}

func TestEvalWithDataAndAllowMissingEscape(t *testing.T) {
	ix := fixtureIx(t)
	dataDir := filepath.Join("..", "..", "testdata", "data")
	evals, _, err := Evaluate(context.Background(), ix, EvalOptions{
		PlanPath:    planPath(t, "violating.json"),
		InputMode:   "raw",
		DataDir:     dataDir,
		QueryPrefix: "data.terraform.iam",
	})
	if err != nil {
		t.Fatal(err)
	}
	deny := evals["data.terraform.iam.deny"]
	if deny == nil || !deny.Fired {
		t.Fatalf("iam deny should fire (contractor is not exempt): %+v", deny)
	}

	// Escape hatch: evaluate anyway, verdict capped by BuildAnswer.
	evals2, types2, err := Evaluate(context.Background(), ix, EvalOptions{
		PlanPath:         planPath(t, "violating.json"),
		InputMode:        "raw",
		QueryPrefix:      "data.terraform.iam",
		AllowMissingData: true,
	})
	if err != nil {
		t.Fatalf("allow-missing-data must permit eval: %v", err)
	}
	ms := Search(ix, SearchParams{Resources: []string{"google_project_iam_member"}})
	ans := BuildAnswer(ix, ms, evals2, types2, []string{"data.exemptions.members"})
	if ans.Verdict == VerdictCovered {
		t.Fatalf("capped verdict must not be covered, got %q", ans.Verdict)
	}
	if !strings.Contains(ans.Capped, "data.exemptions.members") {
		t.Fatalf("cap reason must name the missing data: %q", ans.Capped)
	}
}

func TestEvalRefusedOnBrokenRepo(t *testing.T) {
	ix, err := BuildIndex(filepath.Join("..", "..", "testdata", "broken-policies"))
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = Evaluate(context.Background(), ix, EvalOptions{
		PlanPath:  planPath(t, "violating.json"),
		InputMode: "raw",
	})
	if err == nil || !strings.Contains(err.Error(), "eval refused") {
		t.Fatalf("eval on a broken repo must refuse (D10), got %v", err)
	}
}

func TestVerdictNoPlanIsProbablyCovered(t *testing.T) {
	ix := fixtureIx(t)
	ms := Search(ix, SearchParams{Resources: []string{"google_storage_bucket"}})
	ans := BuildAnswer(ix, ms, nil, nil, nil)
	if ans.Verdict != VerdictProbably {
		t.Fatalf("AST-only verdict = %q, want %q", ans.Verdict, VerdictProbably)
	}
	for _, c := range ans.Claims {
		if c.Essential && c.Evidence != EvidenceAST {
			t.Fatalf("no-plan claims must be backed-by-AST: %+v", c)
		}
	}
}

// --- Explain bundle ----------------------------------------------------------

func TestExplainBundleForRulePath(t *testing.T) {
	ix := fixtureIx(t)
	b, err := BuildBundle(ix, "data.terraform.network.deny")
	if err != nil {
		t.Fatal(err)
	}
	if len(b.Rules) == 0 {
		t.Fatal("bundle must contain the target rule")
	}
	if _, ok := b.Sources[filepath.Join("lib", "helpers.rego")]; !ok {
		t.Fatalf("bundle must include the helper dependency source, got %v", keys(b.Sources))
	}
	out := RenderBundle(b)
	if !strings.Contains(out, "firewall_is_open") || !strings.Contains(out, "deny_open_firewall.rego") {
		t.Fatalf("rendered bundle missing content:\n%s", out[:min(len(out), 400)])
	}
}

func TestExplainBundleUnknownTargetErrors(t *testing.T) {
	ix := fixtureIx(t)
	if _, err := BuildBundle(ix, "data.nope.deny"); err == nil {
		t.Fatal("unknown rule path must error")
	}
	if _, err := BuildBundle(ix, "nope/missing.rego"); err == nil {
		t.Fatal("unknown file must error")
	}
}

// --- Render golden -----------------------------------------------------------

func TestRenderGolden(t *testing.T) {
	ans := Answer{
		Verdict: VerdictCovered,
		Claims: []Claim{
			{Text: "storage/deny_public_bucket.rego:12  deny — fired on plan, matched: allUsers", Evidence: EvidenceEval, Essential: true, Contribution: VerdictCovered},
			{Text: "lib/helpers.rego:9  bucket_iam_is_public — helper, matched: allUsers", Evidence: EvidenceAST},
		},
	}
	got := Render(ans, nil, "")
	want := "Verdict: covered\n" +
		"  1. storage/deny_public_bucket.rego:12  deny — fired on plan, matched: allUsers   [verified-by-eval]\n" +
		"  2. lib/helpers.rego:9  bucket_iam_is_public — helper, matched: allUsers   [backed-by-AST]\n"
	if got != want {
		t.Fatalf("render drifted from golden format:\ngot:\n%s\nwant:\n%s", got, want)
	}
}

func keys(m map[string]string) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}
