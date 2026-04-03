package finding

import (
	"strings"
	"testing"
)

// Every rule must carry guidance. A finding a maintainer cannot act on is
// noise, and the gap would only show up in a report a user is already reading.
func TestEveryRuleHasRemediation(t *testing.T) {
	for _, id := range AllRules() {
		t.Run(string(id), func(t *testing.T) {
			r, err := RemediationFor(id)
			if err != nil {
				t.Fatalf("no remediation: %v", err)
			}
			if strings.TrimSpace(r.Summary) == "" {
				t.Error("empty summary")
			}
			if strings.TrimSpace(r.Why) == "" {
				t.Error("empty rationale")
			}
			if strings.TrimSpace(r.Example) == "" {
				t.Error("empty example")
			}
			if !strings.HasPrefix(r.Docs, "https://") {
				t.Errorf("docs link %q is not an https URL", r.Docs)
			}
		})
	}
}

func TestRemediationForUnknownRule(t *testing.T) {
	if _, err := RemediationFor(RuleID("nonsense")); err == nil {
		t.Fatal("expected an error for an unknown rule")
	}
}

func TestAllRemediationsCoversEveryRule(t *testing.T) {
	if got, want := len(AllRemediations()), len(AllRules()); got != want {
		t.Fatalf("got %d remediations, want %d", got, want)
	}
}
