package main_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

var binPath string

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "regoxplain-e2e")
	if err != nil {
		panic(err)
	}
	binPath = filepath.Join(dir, "regoxplain")
	build := exec.Command("go", "build", "-o", binPath, ".")
	build.Stderr = os.Stderr
	if err := build.Run(); err != nil {
		os.RemoveAll(dir)
		panic("building regoxplain for e2e: " + err.Error())
	}
	// os.Exit skips defers — clean up explicitly or every run leaks a dir.
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

func run(t *testing.T, args ...string) (string, int) {
	t.Helper()
	cmd := exec.Command(binPath, args...)
	// Full config/cache isolation: without HOME/XDG overrides the tests
	// would read the developer's real ~/.config/regoxplain/config.toml —
	// a malformed or alias-bearing config would fail or skew every test.
	iso := t.TempDir()
	cmd.Env = append(os.Environ(),
		"REGOXPLAIN_CACHE_DIR="+t.TempDir(),
		"HOME="+iso,
		"XDG_CONFIG_HOME="+iso,
	)
	out, err := cmd.CombinedOutput()
	code := 0
	if ee, ok := err.(*exec.ExitError); ok {
		code = ee.ExitCode()
	} else if err != nil {
		t.Fatalf("running %v: %v", args, err)
	}
	return string(out), code
}

func fixtures(parts ...string) string {
	return filepath.Join(append([]string{"..", "..", "testdata"}, parts...)...)
}

func TestE2ECoveredVerdict(t *testing.T) {
	out, code := run(t,
		"search", "--repo", fixtures("policies"),
		"--resource", "google_storage_bucket_iam_member",
		"--plan", fixtures("plans", "violating.json"),
	)
	if code != 0 {
		t.Fatalf("exit %d:\n%s", code, out)
	}
	if !strings.Contains(out, "Verdict: covered") || !strings.Contains(out, "[verified-by-eval]") {
		t.Fatalf("want covered verdict with eval evidence:\n%s", out)
	}
	if !strings.Contains(out, "deny_public_bucket.rego:") {
		t.Fatalf("want file:line citation:\n%s", out)
	}
}

func TestE2EHonestMiss(t *testing.T) {
	out, code := run(t, "ask", "--repo", fixtures("policies"), "is the flurblewumpus covered?")
	if code != 0 {
		t.Fatalf("exit %d:\n%s", code, out)
	}
	if !strings.Contains(out, "not proven") || !strings.Contains(out, "no AST evidence") {
		t.Fatalf("miss must be honest:\n%s", out)
	}
}

func TestE2EAskFreeText(t *testing.T) {
	out, code := run(t, "ask", "--repo", fixtures("policies"), "is a public bucket denied?")
	if code != 0 {
		t.Fatalf("exit %d:\n%s", code, out)
	}
	if !strings.Contains(out, "Verdict:") || !strings.Contains(out, "deny") {
		t.Fatalf("free-text ask should reach the storage rules via vocab:\n%s", out)
	}
}

func TestE2EExplainBundle(t *testing.T) {
	out, code := run(t, "explain", "--repo", fixtures("policies"), "data.terraform.network.deny")
	if code != 0 {
		t.Fatalf("exit %d:\n%s", code, out)
	}
	for _, want := range []string{"Explain bundle", "deny_open_firewall.rego", "helpers.rego", "firewall_is_open"} {
		if !strings.Contains(out, want) {
			t.Fatalf("bundle missing %q:\n%s", want, out)
		}
	}
}

func TestE2EWrongFileError(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "plan.out")
	if err := os.WriteFile(bin, []byte("PK\x03\x04\x00binary"), 0o644); err != nil {
		t.Fatal(err)
	}
	out, code := run(t, "eval", "--repo", fixtures("policies"), "--plan", bin, "--query", "data.terraform.storage")
	if code == 0 {
		t.Fatalf("binary planfile must fail:\n%s", out)
	}
	if !strings.Contains(out, "terraform show -json") {
		t.Fatalf("error must name the fix:\n%s", out)
	}
}

func TestE2EUnknownRuleError(t *testing.T) {
	out, code := run(t, "explain", "--repo", fixtures("policies"), "data.nope.deny")
	if code == 0 {
		t.Fatalf("unknown rule must exit non-zero:\n%s", out)
	}
	if !strings.Contains(out, "no rules found") {
		t.Fatalf("error should say no rules found:\n%s", out)
	}
}

func TestE2EMissingDataHardError(t *testing.T) {
	out, code := run(t, "eval", "--repo", fixtures("policies"),
		"--plan", fixtures("plans", "violating.json"), "--query", "data.terraform.iam")
	if code == 0 {
		t.Fatalf("missing data must fail hard:\n%s", out)
	}
	if !strings.Contains(out, "data.exemptions") || !strings.Contains(out, "--allow-missing-data") {
		t.Fatalf("error must name document and escape hatch:\n%s", out)
	}

	out2, code2 := run(t, "eval", "--repo", fixtures("policies"),
		"--plan", fixtures("plans", "violating.json"), "--query", "data.terraform.iam",
		"--data", fixtures("data"))
	if code2 != 0 {
		t.Fatalf("with --data eval should pass, exit %d:\n%s", code2, out2)
	}
	if !strings.Contains(out2, "FIRED") {
		t.Fatalf("iam deny should fire with data supplied:\n%s", out2)
	}
}

// Regression: flags must work AFTER positional args — stdlib flag stops at
// the first positional, which made the documented `explain <rule> --repo .`
// invocation fail with a usage error (and would have folded trailing flags
// into ask's question text).
func TestE2EFlagsAfterPositional(t *testing.T) {
	out, code := run(t, "explain", "data.terraform.network.deny", "--repo", fixtures("policies"))
	if code != 0 || !strings.Contains(out, "deny_open_firewall.rego") {
		t.Fatalf("explain with trailing --repo failed (exit %d):\n%s", code, out)
	}
	out2, code2 := run(t, "ask", "is a public bucket denied?", "--repo", fixtures("policies"))
	if code2 != 0 || !strings.Contains(out2, "Verdict:") {
		t.Fatalf("ask with trailing --repo failed (exit %d):\n%s", code2, out2)
	}
	if strings.Contains(out2, "repo") && strings.Contains(out2, "no AST evidence for: repo") {
		t.Fatalf("trailing flag leaked into the question tokens:\n%s", out2)
	}
}
