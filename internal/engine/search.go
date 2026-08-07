package engine

import (
	"sort"
	"strings"
)

// SearchParams is the structured-first query surface (eng review D2): exact
// and case-insensitive substring matching against indexed refs, rule names,
// and package names. Fully deterministic — no synonym table lives here.
type SearchParams struct {
	Terms     []string // free tokens, matched anywhere
	Resources []string // must match a ref (e.g. google_storage_bucket)
	Attrs     []string // must match a ref (e.g. members)
}

// Match is one rule that matched a search, with the evidence of why.
type Match struct {
	Rule        RuleInfo
	DirectHits  []string // matched terms found in direct refs / names
	IndirectHit []string // matched terms found only via indirect (helper) refs
}

func (m Match) Score() int { return len(m.DirectHits)*2 + len(m.IndirectHit) }

// Search returns matching entrypoint-and-helper rules ranked by match count,
// direct matches above indirect ones. An empty result is first-class: the
// caller renders "no AST evidence" — never "not covered".
func Search(ix *Index, p SearchParams) []Match {
	var out []Match
	for _, r := range ix.Rules {
		m := matchRule(r, p)
		if m == nil {
			continue
		}
		out = append(out, *m)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Score() != out[j].Score() {
			return out[i].Score() > out[j].Score()
		}
		if out[i].Rule.File != out[j].Rule.File {
			return out[i].Rule.File < out[j].Rule.File
		}
		return out[i].Rule.Row < out[j].Rule.Row
	})
	return out
}

func matchRule(r RuleInfo, p SearchParams) *Match {
	m := &Match{Rule: r}
	// Resources and Attrs are filters: every provided list must land at
	// least one hit in the rule's refs, or the rule is out.
	for _, group := range [][]string{p.Resources, p.Attrs} {
		if len(group) == 0 {
			continue
		}
		hit := false
		for _, want := range group {
			direct, indirect := refHit(r, want)
			if direct {
				m.DirectHits = append(m.DirectHits, want)
				hit = true
			} else if indirect {
				m.IndirectHit = append(m.IndirectHit, want)
				hit = true
			}
		}
		if !hit {
			return nil
		}
	}
	// Terms are additive: any term may hit refs, rule name, or package.
	termHit := false
	for _, t := range p.Terms {
		lt := strings.ToLower(t)
		if strings.Contains(strings.ToLower(r.Name), lt) || strings.Contains(strings.ToLower(r.Package), lt) {
			m.DirectHits = append(m.DirectHits, t)
			termHit = true
			continue
		}
		direct, indirect := refHit(r, t)
		if direct {
			m.DirectHits = append(m.DirectHits, t)
			termHit = true
		} else if indirect {
			m.IndirectHit = append(m.IndirectHit, t)
			termHit = true
		}
	}
	if len(p.Terms) > 0 && !termHit && len(p.Resources) == 0 && len(p.Attrs) == 0 {
		return nil
	}
	if len(p.Terms) == 0 && len(p.Resources) == 0 && len(p.Attrs) == 0 {
		return nil
	}
	if len(m.DirectHits) == 0 && len(m.IndirectHit) == 0 {
		return nil
	}
	m.DirectHits = dedupe(m.DirectHits)
	m.IndirectHit = dedupe(m.IndirectHit)
	return m
}

func refHit(r RuleInfo, want string) (direct, indirect bool) {
	lw := strings.ToLower(want)
	for _, ref := range r.Refs {
		if strings.Contains(strings.ToLower(ref.Ref), lw) {
			if ref.Indirect {
				indirect = true
			} else {
				direct = true
			}
		}
	}
	for _, lit := range r.Literals {
		if strings.Contains(strings.ToLower(lit), lw) {
			direct = true
		}
	}
	for _, a := range r.Attrs {
		if strings.Contains(strings.ToLower(a), lw) {
			direct = true
		}
	}
	for _, lit := range r.IndirectLiterals {
		if strings.Contains(strings.ToLower(lit), lw) {
			indirect = true
		}
	}
	for _, a := range r.IndirectAttrs {
		if strings.Contains(strings.ToLower(a), lw) {
			indirect = true
		}
	}
	return
}

var stopwords = map[string]bool{
	"is": true, "a": true, "an": true, "the": true, "are": true, "does": true,
	"do": true, "can": true, "will": true, "any": true, "by": true, "in": true,
	"of": true, "to": true, "for": true, "on": true, "our": true, "my": true,
	"we": true, "this": true, "that": true, "with": true, "covered": true,
	"cover": true, "policy": true, "policies": true, "rule": true, "rules": true,
	"denied": true, "deny": false, // "deny" is a real rule name — keep it
	"allowed": true, "there": true, "what": true, "which": true, "how": true,
}

// AskTokens turns a free-text question into search terms: tokenize, drop
// stopwords, then expand each token through the repo-derived vocabulary and
// user aliases (eng review D7). Returns the expanded terms and the tokens
// that found no vocabulary match (reported honestly by the caller).
func AskTokens(ix *Index, aliases map[string][]string, question string) (terms []string, misses []string) {
	vocab := map[string]bool{}
	for _, v := range ix.Vocab {
		vocab[v] = true
	}
	for _, tok := range tokenize(question) {
		if stopwords[tok] || len(tok) < 2 {
			continue
		}
		expanded := false
		if vocab[tok] {
			terms = append(terms, tok)
			expanded = true
		}
		for _, alias := range aliases[tok] {
			terms = append(terms, alias)
			expanded = true
		}
		if !expanded {
			// substring fallback against vocab entries (still literal)
			for _, v := range ix.Vocab {
				if len(tok) >= 3 && strings.Contains(v, tok) {
					terms = append(terms, v)
					expanded = true
				}
			}
		}
		if !expanded {
			misses = append(misses, tok)
		}
	}
	return dedupe(terms), dedupe(misses)
}
