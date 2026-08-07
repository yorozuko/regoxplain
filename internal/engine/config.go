package engine

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/BurntSushi/toml"
)

// Config lives in one place: ~/.config/regoxplain/config.toml with per-repo
// tables (eng review 2A). input_mode is the 1A adapter setting; aliases are
// the user-growable half of the D7 vocabulary (your own vague words → repo
// terms). The LLM endpoint section arrives with Milestone 3.
type Config struct {
	Aliases map[string][]string   `toml:"aliases"`
	Repos   map[string]RepoConfig `toml:"repos"`
}

type RepoConfig struct {
	InputMode string `toml:"input_mode"`
}

// LoadConfig reads the config file, returning zero-value defaults when the
// file is absent. A malformed file is an error — silent fallback would make
// input_mode quietly wrong, the exact failure the adapter exists to prevent.
func LoadConfig() (*Config, error) {
	cfg := &Config{Aliases: map[string][]string{}, Repos: map[string]RepoConfig{}}
	dir, err := os.UserConfigDir()
	if err != nil {
		return cfg, nil
	}
	path := filepath.Join(dir, "regoxplain", "config.toml")
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return cfg, nil
		}
		return nil, err
	}
	if err := toml.Unmarshal(data, cfg); err != nil {
		return nil, err
	}
	if cfg.Aliases == nil {
		cfg.Aliases = map[string][]string{}
	}
	if cfg.Repos == nil {
		cfg.Repos = map[string]RepoConfig{}
	}
	// Normalize alias keys through the same tokenizer ask() uses — a key
	// like "Public" or "public_access" would otherwise never match any
	// question token and the alias would be silently dead.
	normalized := map[string][]string{}
	for key, vals := range cfg.Aliases {
		for _, tok := range tokenize(key) {
			normalized[tok] = dedupe(append(normalized[tok], vals...))
		}
	}
	cfg.Aliases = normalized
	return cfg, nil
}

// InputModeFor returns the configured input_mode for a repo path, defaulting
// to raw (the conftest convention). Both sides are cleaned and symlink-
// resolved before comparison: on macOS /tmp vs /private/tmp (or a trailing
// slash in the config key) would otherwise silently fall back to raw — the
// exact "quietly wrong input_mode" failure this config exists to prevent.
func (c *Config) InputModeFor(repoPath string) string {
	want := canonicalPath(repoPath)
	for key, rc := range c.Repos {
		if rc.InputMode == "" {
			continue
		}
		if canonicalPath(key) == want {
			return rc.InputMode
		}
	}
	return string(ModeRaw)
}

// CanonicalPath resolves a path to its absolute, symlink-free form — the
// one identity used for config lookups and engine-cache keys ("/tmp" vs
// "/private/tmp" vs a trailing slash must not create distinct engines).
func CanonicalPath(p string) string { return canonicalPath(p) }

func canonicalPath(p string) string {
	abs, err := filepath.Abs(strings.TrimRight(p, "/"))
	if err != nil {
		return p
	}
	if resolved, err := filepath.EvalSymlinks(abs); err == nil {
		return resolved
	}
	return abs
}
