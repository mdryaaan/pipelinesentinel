package cmd

import (
	"fmt"
	"io"
	"os"

	"github.com/mdryaaan/pipelinesentinel/internal/report"
)

// Output formats. They are constants rather than string literals scattered
// across the commands so `audit --format` and `report --format` cannot drift
// apart, which would be a small difference with an annoying failure mode: the
// same word meaning two things depending on which command you typed.
const (
	formatDigest    = "digest"
	formatMarkdown  = "markdown"
	formatMarkdownS = "md"
	formatJSON      = "json"
	formatSARIF     = "sarif"
	formatComment   = "pr-comment"
	formatCommentS  = "comment"
)

// renderAudit writes the audit in the named format.
func renderAudit(out io.Writer, result report.Audit, format string) error {
	switch format {
	case formatDigest:
		return report.WriteDigest(out, result)
	case formatMarkdown, formatMarkdownS:
		return report.WriteMarkdown(out, result)
	case formatJSON:
		return report.WriteJSON(out, result)
	case formatSARIF:
		return report.WriteSARIF(out, result)
	case formatComment, formatCommentS:
		return report.WritePRComment(out, result)
	default:
		return fmt.Errorf("unknown format %q (want %s, %s, %s, %s, or %s)",
			format, formatDigest, formatMarkdown, formatJSON, formatSARIF, formatComment)
	}
}

// writeTo renders to a file when path is set, and to out otherwise.
func writeTo(out io.Writer, result report.Audit, format, path string) error {
	if path == "" {
		return renderAudit(out, result, format)
	}

	file, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("creating %s: %w", path, err)
	}
	defer func() { _ = file.Close() }()

	return renderAudit(file, result, format)
}
