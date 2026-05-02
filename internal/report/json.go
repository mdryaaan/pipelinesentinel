package report

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/mdryaaan/pipelinesentinel/internal/finding"
)

// WriteJSON renders the audit as indented JSON.
//
// This is the machine-readable contract: policy gates read it, dashboards
// ingest it, and diffing two runs is how a team tracks whether a repository is
// getting safer. Field names are therefore treated as stable.
func WriteJSON(w io.Writer, audit Audit) error {
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	// A workflow snippet routinely contains `${{ ... }}` and `<`; escaping them
	// into < makes the JSON unreadable for no security benefit here.
	encoder.SetEscapeHTML(false)

	if err := encoder.Encode(audit); err != nil {
		return fmt.Errorf("encoding audit as JSON: %w", err)
	}
	return nil
}

// WriteSARIF renders the audit in SARIF 2.1.0, which is what GitHub's code
// scanning API accepts.
//
// Emitting SARIF is what turns this from a tool someone runs once into one that
// annotates pull requests: uploaded to code scanning, each finding becomes an
// inline comment on the exact line, in the interface reviewers already use.
func WriteSARIF(w io.Writer, audit Audit) error {
	rules := map[string]sarifRule{}
	results := make([]sarifResult, 0, len(audit.Findings))

	for _, f := range audit.Active() {
		id := string(f.RuleID)
		if _, seen := rules[id]; !seen {
			rule := sarifRule{ID: id}
			rule.ShortDescription.Text = f.Title
			rule.Properties.Tags = []string{"security", "github-actions"}
			rule.DefaultConfiguration.Level = sarifLevel(f)
			rules[id] = rule
		}

		result := sarifResult{RuleID: id, Level: sarifLevel(f)}
		result.Message.Text = f.Detail
		result.Locations = []sarifLocation{{
			PhysicalLocation: sarifPhysicalLocation{
				ArtifactLocation: sarifArtifact{URI: f.File},
				Region:           sarifRegion{StartLine: f.Line},
			},
		}}
		results = append(results, result)
	}

	driverRules := make([]sarifRule, 0, len(rules))
	for _, id := range orderedRuleIDs(audit) {
		if rule, ok := rules[id]; ok {
			driverRules = append(driverRules, rule)
		}
	}

	doc := sarifDocument{
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Version: "2.1.0",
		Runs: []sarifRun{{
			Tool: sarifTool{Driver: sarifDriver{
				Name:           audit.Tool,
				Version:        audit.Version,
				InformationURI: "https://github.com/mdryaaan/pipelinesentinel",
				Rules:          driverRules,
			}},
			Results: results,
		}},
	}

	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(doc); err != nil {
		return fmt.Errorf("encoding SARIF: %w", err)
	}
	return nil
}

// sarifLevel maps the severity ladder onto SARIF's levels.
//
// SARIF has no "critical", so critical and high both become "error". The
// distinction survives in the message text rather than being lost by rounding a
// critical finding down to a warning.
func sarifLevel(f finding.Finding) string {
	switch f.Severity {
	case finding.Critical, finding.High:
		return "error"
	case finding.Medium, finding.Low:
		return "warning"
	default:
		return "note"
	}
}

func orderedRuleIDs(audit Audit) []string {
	seen := map[string]bool{}
	var out []string
	for _, f := range audit.Active() {
		id := string(f.RuleID)
		if !seen[id] {
			seen[id] = true
			out = append(out, id)
		}
	}
	return out
}

type sarifDocument struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID               string `json:"id"`
	ShortDescription struct {
		Text string `json:"text"`
	} `json:"shortDescription"`
	DefaultConfiguration struct {
		Level string `json:"level"`
	} `json:"defaultConfiguration"`
	Properties struct {
		Tags []string `json:"tags"`
	} `json:"properties"`
}

type sarifResult struct {
	RuleID  string `json:"ruleId"`
	Level   string `json:"level"`
	Message struct {
		Text string `json:"text"`
	} `json:"message"`
	Locations []sarifLocation `json:"locations"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifact `json:"artifactLocation"`
	Region           sarifRegion   `json:"region"`
}

type sarifArtifact struct {
	URI string `json:"uri"`
}

type sarifRegion struct {
	StartLine int `json:"startLine"`
}
