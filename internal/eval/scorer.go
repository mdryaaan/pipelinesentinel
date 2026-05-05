package eval

import (
	"fmt"
	"sort"
	"strings"
)

// Prediction is what the detector produced for one case.
type Prediction struct {
	CaseID string
	// Rules is the set of rule IDs that fired.
	Rules []string
	// Lines maps a rule ID to the line its first finding cited.
	Lines map[string]int
	// Err is set when the case could not be audited at all.
	Err error
}

// CaseResult is one scored case.
type CaseResult struct {
	CaseID      string   `json:"case_id"`
	Category    string   `json:"category"`
	Expected    []string `json:"expected"`
	Predicted   []string `json:"predicted"`
	Correct     bool     `json:"correct"`
	LineCorrect *bool    `json:"line_correct,omitempty"`
	Error       string   `json:"error,omitempty"`
}

// RuleScore is precision and recall for one rule.
type RuleScore struct {
	Rule      string  `json:"rule"`
	TP        int     `json:"true_positives"`
	FP        int     `json:"false_positives"`
	FN        int     `json:"false_negatives"`
	Precision float64 `json:"precision"`
	Recall    float64 `json:"recall"`
	F1        float64 `json:"f1"`
}

// Scores is the full evaluation result.
type Scores struct {
	Cases int `json:"cases"`
	// ExactMatches counts cases where the predicted rule set equalled the
	// expected one. This is the strict metric: a case with one correct finding
	// and one spurious one does not count.
	ExactMatches int     `json:"exact_matches"`
	Accuracy     float64 `json:"accuracy"`
	MacroF1      float64 `json:"macro_f1"`
	// CleanCases and CleanCorrect measure the false-positive rate directly,
	// since that is what decides whether anyone keeps the tool switched on.
	CleanCases   int `json:"clean_cases"`
	CleanCorrect int `json:"clean_correct"`
	// LinesChecked and LinesCorrect measure citation accuracy: a finding that
	// names the wrong line sends a reader to innocent code.
	LinesChecked int                       `json:"lines_checked"`
	LinesCorrect int                       `json:"lines_correct"`
	PerRule      []RuleScore               `json:"per_rule"`
	Confusion    map[string]map[string]int `json:"confusion"`
	Results      []CaseResult              `json:"results"`
	Failures     []string                  `json:"failures,omitempty"`
}

// Score compares predictions against the corpus.
//
// Scoring is multi-label: one workflow can legitimately trip several rules, so
// a case is a set comparison rather than a single choice. Precision and recall
// are computed per rule from those set differences, and the macro average
// weights every rule equally — otherwise unpinned-action, which fires on almost
// every real workflow, would dominate the headline number and hide a broken
// script-injection rule.
func Score(corpus Corpus, predictions []Prediction) Scores {
	byID := make(map[string]Prediction, len(predictions))
	for _, p := range predictions {
		byID[p.CaseID] = p
	}

	scores := Scores{
		Cases:     len(corpus.Cases),
		Confusion: newConfusion(corpus),
	}

	counts := map[string]*RuleScore{}
	rule := func(id string) *RuleScore {
		if _, ok := counts[id]; !ok {
			counts[id] = &RuleScore{Rule: id}
		}
		return counts[id]
	}

	for _, tc := range corpus.Cases {
		pred := byID[tc.ID]

		result := CaseResult{
			CaseID:    tc.ID,
			Category:  tc.Category,
			Expected:  normalise(tc.Expected),
			Predicted: normalise(pred.Rules),
		}
		if pred.Err != nil {
			result.Error = pred.Err.Error()
			scores.Failures = append(scores.Failures,
				fmt.Sprintf("%s: %v", tc.ID, pred.Err))
		}

		expected := toSet(tc.Expected)
		predicted := toSet(pred.Rules)

		for id := range expected {
			if predicted[id] {
				rule(id).TP++
			} else {
				rule(id).FN++
			}
		}
		for id := range predicted {
			if !expected[id] {
				rule(id).FP++
			}
		}

		result.Correct = equalSets(expected, predicted)
		if result.Correct {
			scores.ExactMatches++
		}

		if tc.Category == NoFinding {
			scores.CleanCases++
			if len(predicted) == 0 {
				scores.CleanCorrect++
			}
		}

		if tc.ExpectedLine > 0 {
			scores.LinesChecked++
			got := pred.Lines[tc.Category]
			ok := got == tc.ExpectedLine
			result.LineCorrect = &ok
			if ok {
				scores.LinesCorrect++
			}
		}

		row := tc.Category
		for _, col := range confusionColumns(tc, pred) {
			scores.Confusion[row][col]++
		}

		scores.Results = append(scores.Results, result)
	}

	for _, score := range counts {
		score.Precision = ratio(score.TP, score.TP+score.FP)
		score.Recall = ratio(score.TP, score.TP+score.FN)
		score.F1 = harmonic(score.Precision, score.Recall)
		scores.PerRule = append(scores.PerRule, *score)
	}
	sort.Slice(scores.PerRule, func(i, j int) bool {
		return scores.PerRule[i].Rule < scores.PerRule[j].Rule
	})

	if scores.Cases > 0 {
		scores.Accuracy = float64(scores.ExactMatches) / float64(scores.Cases)
	}
	scores.MacroF1 = macroF1(scores.PerRule)

	return scores
}

// confusionColumns decides which cells a case contributes to.
//
// A case that expected a finding and got nothing lands in the "clean" column,
// which is what makes a missed detection visible in the matrix rather than only
// in the recall column.
func confusionColumns(tc Case, pred Prediction) []string {
	predicted := normalise(pred.Rules)
	if len(predicted) == 0 {
		return []string{NoFinding}
	}
	_ = tc
	return predicted
}

func newConfusion(corpus Corpus) map[string]map[string]int {
	categories := corpus.Categories()
	columns := append([]string{}, categories...)
	if !contains(columns, NoFinding) {
		columns = append(columns, NoFinding)
	}

	matrix := make(map[string]map[string]int, len(categories))
	for _, row := range categories {
		matrix[row] = make(map[string]int, len(columns))
		for _, col := range columns {
			matrix[row][col] = 0
		}
	}
	return matrix
}

// CitationAccuracy is the share of checked cases whose finding cited the
// labelled line.
func (s Scores) CitationAccuracy() float64 { return ratio(s.LinesCorrect, s.LinesChecked) }

// CleanAccuracy is the share of safe workflows that produced no finding.
func (s Scores) CleanAccuracy() float64 { return ratio(s.CleanCorrect, s.CleanCases) }

// Summary renders a one-line result for a terminal or a commit status.
func (s Scores) Summary() string {
	return fmt.Sprintf("%d/%d exact (%.1f%%), macro F1 %.3f, %d/%d clean workflows silent",
		s.ExactMatches, s.Cases, s.Accuracy*100, s.MacroF1, s.CleanCorrect, s.CleanCases)
}

func macroF1(scores []RuleScore) float64 {
	if len(scores) == 0 {
		return 0
	}
	var total float64
	for _, s := range scores {
		total += s.F1
	}
	return total / float64(len(scores))
}

func ratio(num, den int) float64 {
	if den == 0 {
		return 0
	}
	return float64(num) / float64(den)
}

func harmonic(precision, recall float64) float64 {
	if precision+recall == 0 {
		return 0
	}
	return 2 * precision * recall / (precision + recall)
}

func toSet(values []string) map[string]bool {
	out := make(map[string]bool, len(values))
	for _, v := range values {
		if v = strings.TrimSpace(v); v != "" {
			out[v] = true
		}
	}
	return out
}

func equalSets(a, b map[string]bool) bool {
	if len(a) != len(b) {
		return false
	}
	for k := range a {
		if !b[k] {
			return false
		}
	}
	return true
}

func normalise(values []string) []string {
	set := toSet(values)
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func contains(values []string, want string) bool {
	for _, v := range values {
		if v == want {
			return true
		}
	}
	return false
}
