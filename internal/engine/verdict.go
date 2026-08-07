package engine

import (
	"fmt"
	"strings"
)

// Verdict tiers and evidence labels are orthogonal dimensions (design doc
// answer model). A claim is one line asserting one fact about one rule.
const (
	VerdictCovered      = "covered"
	VerdictProbably     = "probably covered"
	VerdictNotProven    = "not proven"
	VerdictInconclusive = "not proven (inconclusive)"

	EvidenceEval    = "verified-by-eval"
	EvidenceAST     = "backed-by-AST"
	EvidenceLLMOnly = "unverified LLM opinion"
)

// Claim is one rendered assertion with its provenance.
type Claim struct {
	Text     string
	Evidence string
	// Essential claims (directly-matched entrypoint rules) drive the
	// verdict; helper and absence claims are informational.
	Essential bool
	// contribution to the verdict, one of the Verdict* constants ("" for
	// informational claims)
	Contribution string
}

// Answer is the complete output of a search/ask (optionally with eval).
type Answer struct {
	Verdict string
	Capped  string // non-empty explains why the verdict was capped
	Claims  []Claim
}

// BuildAnswer applies the eval-outcome → verdict mapping table and the
// aggregation rule: verdict computed over directly-matched entrypoint rules
// only, max semantics (any covered → covered; else any probably → probably;
// else not proven). Eng review D8: covered additionally requires the FIRED
// body to be the MATCHED body (tracer-attributed); ambiguous attribution
// degrades to probably covered with a stated reason.
func BuildAnswer(ix *Index, matches []Match, evals map[string]*EvalResult, typesInPlan map[string]bool, allowedMissingData []string) Answer {
	ans := Answer{Verdict: VerdictNotProven}
	sawCovered, sawProbably := false, false

	// Review D3: only the best-scoring match for the question may drive
	// "covered". Fuzzy token expansion can pull in weakly-related rules; if
	// one of those fires while a stronger match stays quiet, the answer must
	// not claim the question itself is covered.
	bestScore := 0
	for _, m := range matches {
		if m.Rule.Kind != "helper" && m.Score() > bestScore {
			bestScore = m.Score()
		}
	}

	for _, m := range matches {
		r := m.Rule
		loc := fmt.Sprintf("%s:%d", r.File, r.Row)
		hits := strings.Join(append(append([]string{}, m.DirectHits...), m.IndirectHit...), ", ")
		if r.Kind == "helper" {
			ind := ""
			if len(m.IndirectHit) > 0 && len(m.DirectHits) == 0 {
				ind = " (indirect)"
			}
			ans.Claims = append(ans.Claims, Claim{
				Text:     fmt.Sprintf("%s  %s — helper%s, matched: %s", loc, r.Name, ind, hits),
				Evidence: EvidenceAST,
			})
			continue
		}

		c := Claim{Essential: true}
		ev, hasEval := evals[r.Path]
		switch {
		case !hasEval || ev == nil:
			// Reachable both when no --plan was given AND when the rule was
			// excluded by --query; the text must not claim the former.
			c.Text = fmt.Sprintf("%s  %s — matched: %s (not evaluated: no plan supplied or excluded by --query)", loc, r.Name, hits)
			c.Evidence = EvidenceAST
			c.Contribution = VerdictProbably
			sawProbably = true

		case ev.Fired && ev.Attributed && bodyFired(ev, r):
			suffix := ""
			if ev.FiredLabel != "" {
				suffix = fmt.Sprintf(" on %s", ev.FiredLabel)
			}
			switch {
			case r.Kind == "warn":
				// A warn detects but does not block (review D1): the verdict
				// tier itself must carry that — annotation alone is not enough
				// for a consumer reading only the top line.
				c.Text = fmt.Sprintf("%s  %s — fired on plan%s [warn-only: detects but does not block], matched: %s", loc, r.Name, suffix, hits)
				c.Evidence = EvidenceEval
				c.Contribution = VerdictProbably
				sawProbably = true
			case m.Score() < bestScore:
				// Weaker match than the best candidate (review D3): a rule
				// that fired but matched the question less well than a rule
				// that stayed quiet must not stamp "covered" on the question.
				c.Text = fmt.Sprintf("%s  %s — fired on plan%s, but a stronger match for this question did not fire (matched: %s)", loc, r.Name, suffix, hits)
				c.Evidence = EvidenceEval
				c.Contribution = VerdictProbably
				sawProbably = true
			default:
				c.Text = fmt.Sprintf("%s  %s — fired on plan%s, matched: %s", loc, r.Name, suffix, hits)
				c.Evidence = EvidenceEval
				c.Contribution = VerdictCovered
				sawCovered = true
			}

		case ev.Fired && ev.Attributed && !bodyFired(ev, r):
			c.Text = fmt.Sprintf("%s  %s — a different %s body fired (not this one); this body did not catch the plan, matched: %s", loc, r.Name, r.Name, hits)
			c.Evidence = EvidenceEval
			c.Contribution = VerdictNotProven

		case ev.Fired && !ev.Attributed:
			c.Text = fmt.Sprintf("%s  %s — %s fired but the tracer could not attribute which body; capped, matched: %s", loc, r.Name, r.Name, hits)
			c.Evidence = EvidenceEval
			c.Contribution = VerdictProbably
			sawProbably = true
			if ans.Capped == "" {
				ans.Capped = "rule fired but body attribution was ambiguous"
			}

		case !ev.Fired && ruleProbative(r, typesInPlan):
			c.Text = fmt.Sprintf("%s  %s — evaluated, did not fire; plan contains a governed resource type — cannot distinguish compliant configuration from a gap on this plan, matched: %s", loc, r.Name, hits)
			c.Evidence = EvidenceEval
			c.Contribution = VerdictInconclusive

		default: // evaluated, did not fire, plan lacks the resource type
			c.Text = fmt.Sprintf("%s  %s — matched: %s; plan has no governed resource of this type — eval not probative", loc, r.Name, hits)
			c.Evidence = EvidenceAST
			c.Contribution = VerdictProbably
			sawProbably = true
		}
		ans.Claims = append(ans.Claims, c)
	}

	switch {
	case sawCovered:
		ans.Verdict = VerdictCovered
	case sawProbably:
		ans.Verdict = VerdictProbably
	default:
		if anyInconclusive(ans.Claims) {
			ans.Verdict = VerdictInconclusive
		} else {
			ans.Verdict = VerdictNotProven
		}
	}

	if len(allowedMissingData) > 0 {
		if ans.Verdict == VerdictCovered {
			ans.Verdict = VerdictProbably
		}
		reason := fmt.Sprintf("evaluated without external data: %s", strings.Join(allowedMissingData, ", "))
		if ans.Capped != "" {
			ans.Capped += "; " + reason // append — never discard an earlier cap reason
		} else {
			ans.Capped = reason
		}
	}
	return ans
}

// bodyFired implements the D8 relevance rule: the specific body that fired
// must be the matched body.
func bodyFired(ev *EvalResult, r RuleInfo) bool {
	for _, b := range ev.FiredBodies {
		if b.File == r.File && b.Row == r.Row {
			return true
		}
	}
	return false
}

// ruleProbative reports whether the plan contains a resource type this rule
// governs (any ref containing a type present in the plan).
func ruleProbative(r RuleInfo, typesInPlan map[string]bool) bool {
	for t := range typesInPlan {
		lt := strings.ToLower(t)
		for _, ref := range r.Refs {
			if strings.Contains(strings.ToLower(ref.Ref), lt) {
				return true
			}
		}
		for _, lit := range r.Literals {
			if strings.Contains(strings.ToLower(lit), lt) {
				return true
			}
		}
		for _, lit := range r.IndirectLiterals {
			if strings.Contains(strings.ToLower(lit), lt) {
				return true
			}
		}
		// Attrs count too (review D3): a rule reaching the type through
		// attribute paths still governs resources present in the plan.
		for _, a := range r.Attrs {
			if strings.Contains(strings.ToLower(a), lt) {
				return true
			}
		}
		for _, a := range r.IndirectAttrs {
			if strings.Contains(strings.ToLower(a), lt) {
				return true
			}
		}
	}
	return false
}

func anyInconclusive(claims []Claim) bool {
	for _, c := range claims {
		if c.Contribution == VerdictInconclusive {
			return true
		}
	}
	return false
}
