package llm

import (
	"errors"
	"reflect"
	"testing"
)

func TestParseReviewAcceptsRealWorldWrappers(t *testing.T) {
	tests := []struct {
		name string
		raw  string
	}{
		{
			name: "bare object",
			raw:  `{"verdict":"exploitable","confidence":0.9,"reasoning":"Any user can open a PR.","cited_lines":[12],"mitigation":"Use env."}`,
		},
		{
			name: "fenced with a language tag",
			raw: "```json\n" +
				`{"verdict":"exploitable","confidence":0.9,"reasoning":"Any user can open a PR.","cited_lines":[12],"mitigation":"Use env."}` +
				"\n```",
		},
		{
			name: "wrapped in prose",
			raw: `Here is my assessment:
{"verdict":"exploitable","confidence":0.9,"reasoning":"Any user can open a PR.","cited_lines":[12],"mitigation":"Use env."}
Let me know if you need more detail.`,
		},
		{
			name: "nested braces inside strings",
			raw:  `{"verdict":"exploitable","confidence":0.9,"reasoning":"The ${{ github.event.issue.title }} value {is} inlined.","cited_lines":[12],"mitigation":"Use env."}`,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseReview(tc.raw)
			if err != nil {
				t.Fatalf("ParseReview failed: %v", err)
			}
			if got.Verdict != VerdictExploitable {
				t.Errorf("verdict = %q, want %q", got.Verdict, VerdictExploitable)
			}
			if len(got.CitedLines) != 1 || got.CitedLines[0] != 12 {
				t.Errorf("cited lines = %v, want [12]", got.CitedLines)
			}
		})
	}
}

func TestParseReviewRejectsInvalidPayloads(t *testing.T) {
	tests := []struct {
		name string
		raw  string
	}{
		{"empty", ""},
		{"no object", "I could not determine an answer."},
		{"unbalanced", `{"verdict":"exploitable","confidence":0.9`},
		{"unknown verdict", `{"verdict":"probably_fine","confidence":0.9,"reasoning":"x"}`},
		{"confidence above one", `{"verdict":"exploitable","confidence":4,"reasoning":"x"}`},
		{"negative confidence", `{"verdict":"exploitable","confidence":-0.2,"reasoning":"x"}`},
		{"empty reasoning", `{"verdict":"exploitable","confidence":0.9,"reasoning":"  "}`},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseReview(tc.raw)
			if err == nil {
				t.Fatal("expected an error")
			}
			if !errors.Is(err, ErrMalformed) {
				t.Errorf("error %v does not wrap ErrMalformed", err)
			}
		})
	}
}

// Models return the right idea under a slightly wrong name often enough that
// failing the whole review over a hyphen would throw away good analysis.
func TestParseReviewNormalisesNearMissVerdicts(t *testing.T) {
	tests := map[string]string{
		"not-exploitable": VerdictNotExploitable,
		"NOT_EXPLOITABLE": VerdictNotExploitable,
		"false positive":  VerdictNotExploitable,
		"true_positive":   VerdictExploitable,
		"Confirmed":       VerdictExploitable,
		"unknown":         VerdictUncertain,
	}

	for input, want := range tests {
		t.Run(input, func(t *testing.T) {
			raw := `{"verdict":"` + input + `","confidence":0.5,"reasoning":"because"}`
			got, err := ParseReview(raw)
			if err != nil {
				t.Fatalf("ParseReview(%q) failed: %v", input, err)
			}
			if got.Verdict != want {
				t.Errorf("verdict = %q, want %q", got.Verdict, want)
			}
		})
	}
}

func TestVerifyCitationsSeparatesFabricatedLines(t *testing.T) {
	tests := []struct {
		name        string
		cited       []int
		first, last int
		wantValid   []int
		wantInvalid []int
	}{
		{"all inside", []int{12, 14}, 10, 20, []int{12, 14}, nil},
		{"one above the excerpt", []int{12, 99}, 10, 20, []int{12}, []int{99}},
		{"one below the excerpt", []int{2, 12}, 10, 20, []int{12}, []int{2}},
		{"boundaries are inclusive", []int{10, 20}, 10, 20, []int{10, 20}, nil},
		{"duplicates collapse", []int{12, 12, 12}, 10, 20, []int{12}, nil},
		{"nothing cited", nil, 10, 20, nil, nil},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			valid, invalid := VerifyCitations(tc.cited, tc.first, tc.last)
			if !reflect.DeepEqual(valid, tc.wantValid) {
				t.Errorf("valid = %v, want %v", valid, tc.wantValid)
			}
			if !reflect.DeepEqual(invalid, tc.wantInvalid) {
				t.Errorf("invalid = %v, want %v", invalid, tc.wantInvalid)
			}
		})
	}
}

// Dismissing a finding hides a possible vulnerability, so the bar is higher
// than for confirming one and "uncertain" must never clear it.
func TestDismissesIsAsymmetric(t *testing.T) {
	tests := []struct {
		name string
		r    Review
		want bool
	}{
		{"confident not_exploitable", Review{Verdict: VerdictNotExploitable, Confidence: 0.9}, true},
		{"exactly at the threshold", Review{Verdict: VerdictNotExploitable, Confidence: DismissThreshold}, true},
		{"hesitant not_exploitable", Review{Verdict: VerdictNotExploitable, Confidence: 0.55}, false},
		{"uncertain never dismisses", Review{Verdict: VerdictUncertain, Confidence: 0.99}, false},
		{"exploitable never dismisses", Review{Verdict: VerdictExploitable, Confidence: 0.99}, false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.r.Dismisses(); got != tc.want {
				t.Errorf("Dismisses() = %v, want %v", got, tc.want)
			}
		})
	}
}
