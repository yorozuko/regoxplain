package engine

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// InputMode declares how work CI feeds the terraform plan to OPA
// (eng review 1A). The captured CI invocation sets this per repo.
type InputMode string

const (
	ModeRaw         InputMode = "raw"          // whole `terraform show -json` doc as input (conftest convention)
	ModeWrapped     InputMode = "wrapped"      // plan nested under an envelope key: wrapped:<key>
	ModePerResource InputMode = "per-resource" // one eval per resource_changes entry
)

// PlanInput is one evaluation input produced by the adapter. Per-resource
// mode yields many; raw and wrapped yield one.
type PlanInput struct {
	Label string // "" for whole-plan, resource address for per-resource
	Value any
}

// AdapterError is a loud, specific input-validation failure (eng review 3A).
// Garbage input must never surface as a soft "eval not probative" verdict.
type AdapterError struct{ msg string }

func (e *AdapterError) Error() string { return e.msg }

func adapterErrf(format string, args ...any) error {
	return &AdapterError{msg: fmt.Sprintf(format, args...)}
}

// LoadPlan reads, validates, and adapts a terraform plan JSON file.
// mode is "raw", "wrapped:<key>", or "per-resource".
func LoadPlan(path string, mode string) ([]PlanInput, map[string]bool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}

	// Binary `terraform plan -out` files are zip archives ("PK...") — the
	// classic wrong-file slip. Catch it with a named fix.
	if bytes.HasPrefix(data, []byte("PK")) || !json.Valid(data) {
		if bytes.HasPrefix(data, []byte("PK")) || bytes.Contains(data[:min(len(data), 512)], []byte{0}) {
			return nil, nil, adapterErrf("%s looks like a binary terraform planfile, not plan JSON — run: terraform show -json <planfile> > plan.json", path)
		}
		return nil, nil, adapterErrf("%s is not valid JSON — expected `terraform show -json` output", path)
	}

	var doc map[string]any
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, nil, adapterErrf("%s is not a JSON object — expected `terraform show -json` output", path)
	}

	key := ""
	m := InputMode(mode)
	if strings.HasPrefix(mode, "wrapped:") {
		m = ModeWrapped
		key = strings.TrimPrefix(mode, "wrapped:")
	}

	plan := doc
	if m == ModeWrapped {
		if key == "" {
			return nil, nil, adapterErrf("input_mode wrapped requires a key: wrapped:<key>")
		}
		inner, ok := doc[key].(map[string]any)
		if !ok {
			return nil, nil, adapterErrf("input_mode wrapped:%s but %s has no object at key %q", key, path, key)
		}
		plan = inner
	}

	if err := validatePlanShape(plan, path); err != nil {
		return nil, nil, err
	}

	types := resourceTypes(plan)

	switch m {
	case ModeRaw:
		return []PlanInput{{Value: doc}}, types, nil
	case ModeWrapped:
		// CI unwraps before OPA sees it; input is the inner plan.
		return []PlanInput{{Value: plan}}, types, nil
	case ModePerResource:
		rcs, _ := plan["resource_changes"].([]any)
		var out []PlanInput
		for _, rc := range rcs {
			rcm, ok := rc.(map[string]any)
			if !ok {
				continue
			}
			addr, _ := rcm["address"].(string)
			out = append(out, PlanInput{Label: addr, Value: rcm})
		}
		if len(out) == 0 {
			return nil, nil, adapterErrf("per-resource mode: %s has an empty resource_changes list", path)
		}
		return out, types, nil
	default:
		return nil, nil, adapterErrf("unknown input_mode %q (want raw, wrapped:<key>, or per-resource)", mode)
	}
}

// validatePlanShape enforces terraform-plan structure: format_version and a
// resource_changes list. Unknown format_version majors fail loudly rather
// than evaluating a schema we do not understand.
func validatePlanShape(plan map[string]any, path string) error {
	fv, hasFV := plan["format_version"].(string)
	_, hasRC := plan["resource_changes"]
	if !hasFV || !hasRC {
		return adapterErrf("%s is JSON but not a terraform plan (missing format_version and/or resource_changes) — expected `terraform show -json` output", path)
	}
	if !strings.HasPrefix(fv, "1.") && !strings.HasPrefix(fv, "0.") {
		return adapterErrf("%s has plan format_version %q which this tool does not recognize — verdicts would be unreliable; file an issue with your terraform version", path, fv)
	}
	return nil
}

// resourceTypes collects the set of resource types present in the plan —
// the probe behind the "plan lacks any resource of the queried type" row of
// the verdict table.
func resourceTypes(plan map[string]any) map[string]bool {
	out := map[string]bool{}
	rcs, _ := plan["resource_changes"].([]any)
	for _, rc := range rcs {
		if rcm, ok := rc.(map[string]any); ok {
			if t, ok := rcm["type"].(string); ok {
				out[t] = true
			}
		}
	}
	return out
}
