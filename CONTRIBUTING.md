# Contributing to pipelinesentinel

Thanks for taking a look. This document covers what the project expects from a
change, and — more usefully — *why*, so you can tell when a rule here does not
apply to what you are doing.

## Getting set up

```bash
git clone https://github.com/mdryaaan/pipelinesentinel.git
cd pipelinesentinel

make build     # → bin/pipelinesentinel
make test      # go test ./... -race with coverage
make eval      # score the detector against the labelled corpus
make demo      # audit the bundled workflows, no network needed
make ci        # everything the pipeline runs
```

Go 1.22 or newer. No other tooling is required; `golangci-lint` is used if it is
installed and skipped politely if it is not.

## The one rule that matters

**A finding must be true, and it must point at the right line.**

Everything else in this document follows from that. A false positive teaches
people to ignore the tool, and a finding that cites the wrong line sends a
reviewer to read innocent code and conclude the tool is broken. Both are worse
than the finding not existing.

This is why the eval corpus scores line accuracy as a first-class metric, and
why twelve of its forty-five cases are safe workflows that must produce nothing
at all.

## Adding a rule

A new rule needs five things. Skipping any of them will be caught in review:

1. **The rule itself** in `internal/rules/`, implementing the `Rule` interface.
   Use the shared helpers in `rule.go` — `expressions`, `untrustedIn`,
   `lineWithin`, `stepLabel` — rather than writing new regexes for the same job.

2. **A `Confidence` that is honest.** `Certain` means the pattern is definitely
   present and definitely exploitable. `Ambiguous` means exploitability depends
   on context the rule cannot see, and is what routes a finding to the reasoning
   pass. Marking something `Certain` because you would rather not think about
   the edge case is how a tool earns a reputation for noise.

3. **Table-driven tests** in `internal/rules/<rule>_test.go`, including the
   cases the rule must **not** fire on. A test file with only positive cases has
   not tested anything interesting. Assert the cited line with
   `assertCitesLineContaining` — not the count of findings.

4. **A remediation entry** in `internal/finding/remediation.go`: a summary, the
   rationale, a worked example of the safe pattern, and a link to upstream docs.
   A finding a maintainer cannot act on is noise with extra steps.

5. **Corpus cases** in `testdata/eval/`: at least five positive and one or two
   safe look-alikes, with `expected_line` set. Then run `make eval` — CI gates
   on `--min-score 1.0`, so a rule that regresses another rule's score fails the
   build.

## Changing an existing rule

Run `make eval` before and after. If the score moves, one of two things is true
and you should say which in the pull request:

- **The corpus was wrong.** Fix the label, and explain why the old one was
  mistaken.
- **The rule changed behaviour.** Add the case that motivated the change, and
  make sure the existing cases still pass for the right reasons.

Silently updating a label to match new behaviour turns the corpus into a
rubber stamp.

## Working on the parser

`internal/parser` exists to keep the source position of every value, because
line numbers are the thing users actually check. Two traps:

- **YAML 1.1 parses a bare `on:` as the boolean `true`.** Both keys must be
  looked up, or every trigger-dependent rule silently finds nothing.
- **A block scalar's node position points at the `|` marker**, not at the first
  line of the script. `BlockBodyPos` corrects for it and `LineOffset` walks
  within the block. Any new code that reports a line inside a multi-line value
  must go through them.

Both are covered by tests that assert against literal fixture content, so a
regression fails loudly rather than shifting every report by one line.

## Working on the reasoning pass

The model is not allowed to create findings, and it is not allowed to be trusted
on citations. If you are changing `internal/llm`, hold those two lines:

- A provider only ever receives a finding the rules already raised.
- `VerifyCitations` runs on every response. Anything outside the excerpt is
  stripped and counted, never rendered.
- Dismissal is asymmetric on purpose: only `not_exploitable` at confidence ≥ 0.7
  suppresses a finding, and `uncertain` never does. If you find yourself
  lowering that threshold, write down what you expect to gain.

## The offline provider is not a model

`internal/llm/offline.go` applies hand-written heuristics. It exists so the
pipeline runs with no daemon and no key, and so a real model has a labelled
control to be measured against.

**Any output derived from it must carry `OfflineDisclaimer`.** That is enforced
in the verdict text, in every report renderer, on stderr, and by tests. If you
add a new output format, add the disclaimer test with it. Publishing heuristic
output as model accuracy would be a fabricated measurement, and this is the
mechanism that stops it happening by accident.

## Style

- Run `make fmt` before pushing. CI fails on unformatted files and an untidy
  `go.mod`.
- Comments explain **why**, not what. `// increment i` is noise;
  `// A tag is a mutable pointer, so...` is the reason the code exists.
- Errors say what to do next. `"is ollama serve running?"` beats
  `"connection refused"`.
- Exported identifiers get doc comments. `revive` enforces it.

## Commit messages

Conventional commits, present tense, describing the change:

```
feat(rules): add unpinned action rule
fix(parser): correct line offset in nested yaml blocks
test(eval): add labelled cases for script injection
docs: explain why ollama is the default provider
```

## Pull requests

Include:

- What changed and why.
- `make eval` output if you touched a rule, the parser, or the corpus.
- The false positives you checked for, if you added a rule.

Small pull requests get reviewed faster than large ones, and a pull request that
adds one rule with its tests, its remediation, and its corpus cases is exactly
the right size.

## Reporting a security issue

If you find a vulnerability **in pipelinesentinel itself**, please open a private
security advisory on the repository rather than a public issue.

Findings about workflows in other people's repositories are what the tool is for
— report those to the repository's own maintainers, not here.

## License

By contributing you agree that your contributions are licensed under the MIT
License, the same as the rest of the project.
