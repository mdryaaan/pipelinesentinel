package github

import (
	"context"
	"fmt"
	"sort"

	gh "github.com/google/go-github/v66/github"
	"github.com/mdryaaan/pipelinesentinel/internal/utils"
)

// RepoSource fetches a repository's workflows over the API.
type RepoSource struct {
	client *Client
	owner  string
	repo   string
	ref    string
}

// NewRepoSource builds a source for owner/repo. An empty ref means the
// repository's default branch.
func NewRepoSource(client *Client, owner, repo, ref string) *RepoSource {
	return &RepoSource{client: client, owner: owner, repo: repo, ref: ref}
}

// Name describes the source.
func (s *RepoSource) Name() string {
	if s.ref != "" {
		return fmt.Sprintf("%s/%s@%s", s.owner, s.repo, s.ref)
	}
	return fmt.Sprintf("%s/%s", s.owner, s.repo)
}

// Workflows lists and downloads every workflow definition in the repository.
//
// The listing and each download are retried independently: a secondary rate
// limit part-way through would otherwise throw away the files already fetched
// and spend the same budget again on the next run.
func (s *RepoSource) Workflows(ctx context.Context) ([]WorkflowFile, error) {
	entries, err := s.list(ctx)
	if err != nil {
		return nil, err
	}

	out := make([]WorkflowFile, 0, len(entries))
	for _, entry := range entries {
		content, err := s.download(ctx, entry)
		if err != nil {
			return nil, err
		}
		out = append(out, content)
	}

	if len(out) == 0 {
		return nil, fmt.Errorf("%s has no workflow files under %s", s.Name(), WorkflowsDir)
	}

	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out, nil
}

func (s *RepoSource) list(ctx context.Context) ([]*gh.RepositoryContent, error) {
	opts := &gh.RepositoryContentGetOptions{Ref: s.ref}

	var entries []*gh.RepositoryContent
	err := utils.Do(ctx, utils.DefaultRetry(), func(int) error {
		_, dir, resp, err := s.client.api.Repositories.GetContents(
			ctx, s.owner, s.repo, WorkflowsDir, opts)
		if err != nil {
			return s.client.wrap(fmt.Sprintf("listing %s in %s", WorkflowsDir, s.Name()), resp, err)
		}
		s.client.Rate = rateFrom(resp)

		entries = nil
		for _, item := range dir {
			if item.GetType() != "file" || !IsWorkflowFile(item.GetName()) {
				continue
			}
			entries = append(entries, item)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return entries, nil
}

func (s *RepoSource) download(ctx context.Context, entry *gh.RepositoryContent) (WorkflowFile, error) {
	file := WorkflowFile{
		Path: entry.GetPath(),
		Repo: fmt.Sprintf("%s/%s", s.owner, s.repo),
		URL:  entry.GetHTMLURL(),
	}

	// Small files arrive inline with the listing, so the extra round trip is
	// only paid when GitHub actually withheld the content.
	if body, err := decodeInline(entry); err == nil && len(body) > 0 {
		file.Content = body
		return file, nil
	}

	err := utils.Do(ctx, utils.DefaultRetry(), func(int) error {
		content, _, resp, err := s.client.api.Repositories.GetContents(
			ctx, s.owner, s.repo, entry.GetPath(), &gh.RepositoryContentGetOptions{Ref: s.ref})
		if err != nil {
			return s.client.wrap("downloading "+entry.GetPath(), resp, err)
		}
		s.client.Rate = rateFrom(resp)

		body, err := decodeInline(content)
		if err != nil {
			return fmt.Errorf("decoding %s: %w", entry.GetPath(), err)
		}
		file.Content = body
		return nil
	})
	if err != nil {
		return WorkflowFile{}, err
	}
	return file, nil
}

// decodeInline reads the content field of a repository entry.
//
// go-github's GetContent handles the base64 envelope, but it returns an empty
// string with no error when the API withheld the body — which is the case this
// function exists to distinguish, since the caller must then pay a second round
// trip rather than audit an empty file and report it clean.
func decodeInline(entry *gh.RepositoryContent) ([]byte, error) {
	if entry == nil || entry.Content == nil {
		return nil, nil
	}
	if entry.GetEncoding() == "none" {
		return nil, fmt.Errorf("file is too large for the contents API")
	}

	body, err := entry.GetContent()
	if err != nil {
		return nil, err
	}
	return []byte(body), nil
}
