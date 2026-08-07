package engine

import (
	"os"
	"path/filepath"

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
	return cfg, nil
}

// InputModeFor returns the configured input_mode for a repo path, defaulting
// to raw (the conftest convention).
func (c *Config) InputModeFor(repoPath string) string {
	abs, err := filepath.Abs(repoPath)
	if err == nil {
		if rc, ok := c.Repos[abs]; ok && rc.InputMode != "" {
			return rc.InputMode
		}
	}
	return string(ModeRaw)
}
