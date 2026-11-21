package main

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"

	"github.com/bytedance/sonic"

	"github.com/heynemann/go-plg-s3-registry/internal/registry"
	"github.com/heynemann/go-plg-s3-registry/internal/rollout"
)

type githubDeployment struct {
	Repository   string `json:"repository"`
	RepositoryID int64  `json:"repository_id"`
	Branch       string `json:"branch"`
}

var githubRepository = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}$`)
var githubCommit = regexp.MustCompile(`^[0-9a-f]{40}$`)

func (g githubDeployment) valid() bool {
	owner, repo, _ := strings.Cut(g.Repository, "/")
	return g.RepositoryID > 0 && githubRepository.MatchString(g.Repository) && owner != "." && owner != ".." && repo != "." && repo != ".." && g.Branch != "" && len(g.Branch) <= 255
}

func (g githubDeployment) evidence(ctx context.Context, session, role string) (*rollout.Provenance, error) {
	token := os.Getenv("PLG_GITHUB_TOKEN")
	client := http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return g.verify(ctx, &client, "https://api.github.com", token, session, role)
}

func (g githubDeployment) verify(ctx context.Context, client *http.Client, base, token, session, role string) (*rollout.Provenance, error) {
	denied := fmt.Errorf("%w: GitHub run and independent environment review are required", registry.ErrDenied)
	// GitHub's approval history is per run, not per attempt. Require a fresh
	// dispatch; the same command ID can still reconcile a lost response.
	runText, ok := strings.CutPrefix(session, "plg-")
	runText, first := strings.CutSuffix(runText, "-1")
	runID, err := strconv.ParseInt(runText, 10, 64)
	if !ok || !first || err != nil || runID <= 0 || strconv.FormatInt(runID, 10) != runText || token == "" {
		return nil, denied
	}
	root := base + "/repos/" + g.Repository + "/actions/runs/" + runText
	type user struct {
		ID int64 `json:"id"`
	}
	var run struct {
		ID         int64  `json:"id"`
		Attempt    int    `json:"run_attempt"`
		Branch     string `json:"head_branch"`
		Commit     string `json:"head_sha"`
		Path       string `json:"path"`
		Event      string `json:"event"`
		Actor      user   `json:"actor"`
		Trigger    user   `json:"triggering_actor"`
		Repository struct {
			ID int64 `json:"id"`
		} `json:"repository"`
	}
	if err := githubRead(ctx, client, root+"/attempts/1", token, &run); err != nil {
		return nil, err
	}
	if run.ID != runID || run.Attempt != 1 || run.Repository.ID != g.RepositoryID || run.Actor.ID <= 0 || run.Actor != run.Trigger ||
		run.Event != "workflow_dispatch" || run.Branch != g.Branch || !githubCommit.MatchString(run.Commit) ||
		run.Path != ".github/workflows/control-apply.yml" {
		return nil, denied
	}
	var reviews []struct {
		State        string `json:"state"`
		User         user   `json:"user"`
		Environments []struct {
			Name string `json:"name"`
		} `json:"environments"`
	}
	if err := githubRead(ctx, client, root+"/approvals", token, &reviews); err != nil {
		return nil, err
	}
	var reviewer int64
	for _, review := range reviews {
		for _, environment := range review.Environments {
			if environment.Name != "control-"+role {
				continue
			}
			if review.State != "approved" || review.User.ID <= 0 || review.User.ID == run.Actor.ID || reviewer != 0 {
				return nil, denied
			}
			reviewer = review.User.ID
		}
	}
	if reviewer == 0 {
		return nil, denied
	}
	return &rollout.Provenance{Repository: g.Repository, RepositoryID: g.RepositoryID, Run: run.ID, Commit: run.Commit, Initiator: run.Actor.ID, Reviewer: reviewer}, nil
}

func githubRead(ctx context.Context, client *http.Client, url, token string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("read GitHub workflow provenance: HTTP %d", resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, registry.MaxRecordBytes+1))
	if err != nil {
		return err
	}
	if len(data) > registry.MaxRecordBytes || sonic.ConfigStd.Unmarshal(data, out) != nil {
		return fmt.Errorf("invalid GitHub workflow provenance")
	}
	return nil
}
