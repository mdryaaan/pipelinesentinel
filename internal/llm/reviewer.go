package llm

import (
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/mdryaaan/pipelinesentinel/internal/finding"
	"github.com/mdryaaan/pipelinesentinel/internal/parser"
)

// ContextLines is how much workflow surrounds the cited line in the excerpt
// sent to the model. Wide enough to show the step's trigger-adjacent context,
// narrow enough that the model cannot cite half the file and call it evidence.
const ContextLines = 12

// Reviewer escalates ambiguous findings to a provider.
//
// The escalation is deliberately narrow. Certain findings are never sent: the
// rules already answered those correctly and spending inference on them only
// creates an opportunity for a model to overturn a correct result it has no
// better information about. Only findings the rules themselves marked ambiguous
// reach the model.
type Reviewer struct {
	provider Provider
	// Warn receives non-fatal problems — a failed review, a fabricated
	// citation. Nil discards them.
	Warn io.Writer
}

// NewReviewer builds a reviewer over a provider.
func NewReviewer(p Provider) *Reviewer { return &Reviewer{provider: p} }

// Stats summarises what one escalation pass did.
type Stats struct {
	Candidates   int    `json:"candidates"`
	Reviewed     int    `json:"reviewed"`
	Dismissed    int    `json:"dismissed"`
	Confirmed    int    `json:"confirmed"`
	Uncertain    int    `json:"uncertain"`
	Failed       int    `json:"failed"`
	Fabricated   int    `json:"fabricated_citations"`
	TotalCited   int    `json:"total_citations"`
	ProviderName string `json:"provider"`
	ModelName    string `json:"model"`
}

// CitationAccuracy is the share of citations that pointed at a line the model
// was actually shown.
func (s Stats) CitationAccuracy() float64 {
	if s.TotalCited == 0 {
		return 0
	}
	return float64(s.TotalCited-s.Fabricated) / float64(s.TotalCited)
}

// Review escalates every ambiguous finding and annotates it in place.
//
// A provider failure is never fatal. The rules already produced a usable audit;
// losing the reasoning pass degrades it, and reporting nothing because a local
// daemon was not running would be a much worse outcome than reporting the
// deterministic findings with a note.
func (r *Reviewer) Review(
	ctx context.Context, wf *parser.Workflow, findings []finding.Finding,
) ([]finding.Finding, Stats) {
	stats := Stats{ProviderName: r.provider.Name(), ModelName: r.provider.Model()}

	for i := range findings {
		if !findings[i].NeedsReasoning() {
			continue
		}
		stats.Candidates++

		req := r.buildRequest(wf, findings[i])

		review, err := r.provider.Review(ctx, req)
		if err != nil {
			stats.Failed++
			r.warnf("could not review %s: %v", findings[i].Location(), err)
			continue
		}

		valid, invalid := VerifyCitations(review.CitedLines, req.FirstLine, req.LastLine)
		stats.TotalCited += len(valid) + len(invalid)
		stats.Fabricated += len(invalid)
		if len(invalid) > 0 {
			r.warnf("%s: dropped %d citation(s) pointing outside lines %d-%d: %v",
				findings[i].Location(), len(invalid), req.FirstLine, req.LastLine, invalid)
		}

		stats.Reviewed++
		r.apply(&findings[i], review, valid, invalid)

		switch {
		case findings[i].Dismissed:
			stats.Dismissed++
		case review.Verdict == VerdictExploitable:
			stats.Confirmed++
		default:
			stats.Uncertain++
		}
	}

	return findings, stats
}

// apply writes the review onto the finding.
func (r *Reviewer) apply(f *finding.Finding, review Review, valid, invalid []int) {
	f.LLMReviewed = true
	f.LLMVerdict = review.Verdict
	f.LLMScore = review.Confidence
	f.CitedLines = valid
	f.Hallucinated = invalid

	reasoning := review.Reasoning
	if review.Mitigation != "" {
		reasoning += " Suggested change: " + review.Mitigation
	}

	if review.Dismisses() {
		f.Dismissed = true
		f.DismissedWhy = reasoning
		return
	}

	// A confirmed finding graduates out of ambiguity, so a second pass will not
	// pay to ask the same question again.
	if review.Verdict == VerdictExploitable {
		f.Confidence = finding.Probable
	}
	f.Detail = strings.TrimSpace(f.Detail) + "\n\nReasoning pass: " + reasoning
}

// buildRequest assembles the excerpt and metadata for one finding.
func (r *Reviewer) buildRequest(wf *parser.Workflow, f finding.Finding) Request {
	first := f.Line - ContextLines
	if first < 1 {
		first = 1
	}
	last := f.Line + ContextLines
	if total := wf.LineCount(); last > total {
		last = total
	}

	triggers := make([]string, 0, len(wf.Triggers))
	for _, t := range wf.Triggers {
		triggers = append(triggers, t.Value)
	}

	return Request{
		RuleID:      string(f.RuleID),
		Title:       f.Title,
		Detail:      f.Detail,
		File:        f.File,
		Line:        f.Line,
		Job:         f.Job,
		Step:        f.Step,
		Triggers:    triggers,
		Permissions: describePermissions(wf, f.Job),
		Context:     wf.Excerpt(first, last),
		FirstLine:   first,
		LastLine:    last,
	}
}

// describePermissions renders the effective permissions for a job, since that
// is what decides how much a successful exploit is worth.
func describePermissions(wf *parser.Workflow, jobID string) string {
	for _, job := range wf.Jobs {
		if job.ID.Value == jobID && job.Permissions.Declared {
			return renderPermissions(job.Permissions) + " (job level)"
		}
	}
	if wf.Permissions.Declared {
		return renderPermissions(wf.Permissions) + " (workflow level)"
	}
	return ""
}

func renderPermissions(p parser.Permissions) string {
	if !p.Blanket.Empty() {
		return p.Blanket.Value
	}
	parts := make([]string, 0, len(p.Scopes))
	for name, value := range p.Scopes {
		parts = append(parts, fmt.Sprintf("%s: %s", name, value.Value))
	}
	if len(parts) == 0 {
		return "(empty)"
	}
	sortStrings(parts)
	return strings.Join(parts, ", ")
}

func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}

func (r *Reviewer) warnf(format string, args ...any) {
	if r.Warn == nil {
		return
	}
	fmt.Fprintf(r.Warn, "pipelinesentinel: "+format+"\n", args...)
}
