// Command pipelinesentinel audits GitHub Actions workflows for supply-chain
// security risks.
package main

import (
	"embed"
	"io/fs"
	"log"
	"os"

	"github.com/mdryaaan/pipelinesentinel/cmd"
)

// The fixtures and the eval corpus are compiled in so `--offline` and `eval`
// work from any directory, in any container, with no network. They live at the
// repository root because the tests read them from there too, and a second copy
// under a package directory would drift from the first.
//
//go:embed all:testdata/fixtures
var fixtures embed.FS

//go:embed all:testdata/eval
var evalCorpus embed.FS

func main() {
	fixtureFS, err := fs.Sub(fixtures, "testdata/fixtures")
	if err != nil {
		log.Fatalf("pipelinesentinel: %v", err)
	}
	evalFS, err := fs.Sub(evalCorpus, "testdata/eval")
	if err != nil {
		log.Fatalf("pipelinesentinel: %v", err)
	}

	cmd.SetEmbedded(fixtureFS, evalFS)
	os.Exit(cmd.Execute())
}
