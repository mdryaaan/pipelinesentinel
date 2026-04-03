package llm

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// Verdicts the model may return.
const (
	VerdictExploitable    = "exploitable"
	VerdictNotExploitable = "not_exploitable"
	VerdictUncertain      = "uncertain"
)

// Review is a validated adjudication of one ambiguous finding.
type Review struct {
	Verdict    string  `json:"verdict"`
	Confidence float64 `json:"confidence"`
	Reasoning  string  `json:"reasoning"`
	// CitedLines are line numbers from the excerpt the model says support its
	// verdict. Verified against the excerpt before they are shown to anyone.
	CitedLines []int `json:"cited_lines"`
	// Hallucinated holds citations that pointed outside the excerpt.
	Hallucinated []int  `json:"hallucinated_lines,omitempty"`
	Mitigation   string `json:"mitigation"`
}

// rawReview mirrors the JSON contract exactly. It is a separate type from
// Review so a model cannot set fields pipelinesentinel computes itself, such as
// Hallucinated.
type rawReview struct {
	Verdict    string  `json:"verdict"`
	Confidence float64 `json:"confidence"`
	Reasoning  string  `json:"reasoning"`
	CitedLines []int   `json:"cited_lines"`
	Mitigation string  `json:"mitigation"`
}

// SchemaJSON is the contract shown to the model in the prompt.
const SchemaJSON = `{
  "verdict": "one of: exploitable | not_exploitable | uncertain",
  "confidence": 0.0,
  "reasoning": "two or three sentences naming the specific attacker and the specific path",
  "cited_lines": [12, 13],
  "mitigation": "one concrete change to the workflow"
}`

// ValidVerdict reports whether v is one of the three allowed verdicts.
func ValidVerdict(v string) bool {
	switch v {
	case VerdictExploitable, VerdictNotExploitable, VerdictUncertain:
		return true
	}
	return false
}

// Validate checks a review against the schema's invariants.
func (r Review) Validate() error {
	if !ValidVerdict(r.Verdict) {
		return fmt.Errorf("%w: verdict %q is not one of %s, %s, %s",
			ErrMalformed, r.Verdict, VerdictExploitable, VerdictNotExploitable, VerdictUncertain)
	}
	if r.Confidence < 0 || r.Confidence > 1 {
		return fmt.Errorf("%w: confidence %v is outside [0,1]", ErrMalformed, r.Confidence)
	}
	if strings.TrimSpace(r.Reasoning) == "" {
		return fmt.Errorf("%w: empty reasoning", ErrMalformed)
	}
	return nil
}

// Dismisses reports whether this review should suppress the finding.
//
// A dismissal has to clear a bar that a confirmation does not. Confirming a
// finding the rules already raised costs a maintainer a few minutes of reading;
// dismissing one hides a real vulnerability, and the model is working from an
// excerpt with no knowledge of the repository's settings, its branch
// protections, or who can open a pull request. So only a confident
// not_exploitable dismisses, and "uncertain" never does.
func (r Review) Dismisses() bool {
	return r.Verdict == VerdictNotExploitable && r.Confidence >= DismissThreshold
}

// DismissThreshold is the confidence a not_exploitable verdict must reach
// before it suppresses a finding.
const DismissThreshold = 0.7

// ParseReview extracts and validates a review from a raw model response.
//
// Models wrap JSON in prose or fenced code blocks often enough that demanding a
// bare object would fail constantly, so the object is located inside the
// response rather than assumed to be the whole of it. Anything that still does
// not satisfy the schema is rejected: the caller retries once and then gives up
// honestly rather than guessing.
func ParseReview(raw string) (Review, error) {
	payload, err := extractJSONObject(raw)
	if err != nil {
		return Review{}, err
	}

	var rr rawReview
	if err := json.NewDecoder(strings.NewReader(payload)).Decode(&rr); err != nil {
		return Review{}, fmt.Errorf("%w: %w", ErrMalformed, err)
	}

	review := Review{
		Verdict:    normaliseVerdict(rr.Verdict),
		Confidence: rr.Confidence,
		Reasoning:  strings.TrimSpace(rr.Reasoning),
		CitedLines: rr.CitedLines,
		Mitigation: strings.TrimSpace(rr.Mitigation),
	}

	if err := review.Validate(); err != nil {
		return Review{}, err
	}
	return review, nil
}

// normaliseVerdict accepts the near-misses models actually produce rather than
// failing a whole review over a hyphen.
func normaliseVerdict(v string) string {
	v = strings.ToLower(strings.TrimSpace(v))
	v = strings.ReplaceAll(v, "-", "_")
	v = strings.ReplaceAll(v, " ", "_")

	switch v {
	case "exploitable", "true_positive", "confirmed":
		return VerdictExploitable
	case "not_exploitable", "false_positive", "notexploitable", "safe":
		return VerdictNotExploitable
	case "uncertain", "unknown", "unsure":
		return VerdictUncertain
	}
	return v
}

// VerifyCitations splits the model's citations into ones that fall inside the
// excerpt it was given and ones that do not.
//
// A cited line number reads as evidence, so a number pointing at code the model
// never saw manufactures false confidence — which is worse than citing nothing
// at all. Prompting against it is a first line of defence, not a guarantee;
// this is the check that actually holds.
func VerifyCitations(cited []int, first, last int) (valid, invalid []int) {
	seen := make(map[int]bool, len(cited))
	for _, line := range cited {
		if seen[line] {
			continue
		}
		seen[line] = true

		if line >= first && line <= last {
			valid = append(valid, line)
		} else {
			invalid = append(invalid, line)
		}
	}

	sort.Ints(valid)
	sort.Ints(invalid)
	return valid, invalid
}

// extractJSONObject finds the first balanced top-level JSON object in s,
// tolerating markdown fences and surrounding commentary.
func extractJSONObject(s string) (string, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", fmt.Errorf("%w: empty response", ErrMalformed)
	}

	if idx := strings.Index(s, "```"); idx >= 0 {
		rest := s[idx+3:]
		if nl := strings.IndexByte(rest, '\n'); nl >= 0 {
			rest = rest[nl+1:]
		}
		if end := strings.Index(rest, "```"); end >= 0 {
			rest = rest[:end]
		}
		s = strings.TrimSpace(rest)
	}

	start := strings.IndexByte(s, '{')
	if start < 0 {
		return "", fmt.Errorf("%w: no JSON object found", ErrMalformed)
	}

	depth := 0
	inString := false
	escaped := false

	for i := start; i < len(s); i++ {
		c := s[i]
		switch {
		case escaped:
			escaped = false
		case c == '\\' && inString:
			escaped = true
		case c == '"':
			inString = !inString
		case inString:
			// structural characters inside strings are just text
		case c == '{':
			depth++
		case c == '}':
			depth--
			if depth == 0 {
				return s[start : i+1], nil
			}
		}
	}

	return "", fmt.Errorf("%w: unbalanced JSON object", ErrMalformed)
}
