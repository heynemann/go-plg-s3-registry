package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/heynemann/go-plg-s3-registry/internal/registry"
	"github.com/heynemann/go-plg-s3-registry/internal/rollout"
)

func TestGitHubControlProvenance(t *testing.T) {
	config := githubDeployment{Repository: "example/control", RepositoryID: 42, Branch: "main"}
	commit := strings.Repeat("a", 40)
	for _, tc := range []struct {
		name, session, environment string
		repository, reviewer       int64
		want                       bool
	}{
		{"reviewed", "plg-76-1", "control-approver", 42, 99, true},
		{"self review", "plg-76-1", "control-approver", 42, 12, false},
		{"another role", "plg-76-1", "control-decider", 42, 99, false},
		{"repository replaced", "plg-76-1", "control-approver", 43, 99, false},
		{"reused past review", "plg-76-2", "control-approver", 42, 99, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("Authorization") != "Bearer fixture" {
					http.Error(w, "no credential", http.StatusUnauthorized)
					return
				}
				switch r.URL.Path {
				case "/repos/example/control/actions/runs/76/attempts/1":
					_, _ = fmt.Fprintf(w, `{"id":76,"run_attempt":1,"head_branch":"main","head_sha":%q,"path":".github/workflows/control-apply.yml","event":"workflow_dispatch","actor":{"id":12},"triggering_actor":{"id":12},"repository":{"id":%d}}`, commit, tc.repository)
				case "/repos/example/control/actions/runs/76/approvals":
					_, _ = fmt.Fprintf(w, `[{"state":"approved","user":{"id":%d},"environments":[{"name":%q}]}]`, tc.reviewer, tc.environment)
				default:
					http.NotFound(w, r)
				}
			}))
			defer s.Close()
			got, err := config.verify(t.Context(), s.Client(), s.URL, "fixture", tc.session, "approver")
			if !tc.want {
				require.ErrorIs(t, err, registry.ErrDenied)
				return
			}
			require.NoError(t, err)
			require.Equal(t, &rollout.Provenance{Repository: config.Repository, RepositoryID: 42, Run: 76, Commit: commit, Initiator: 12, Reviewer: 99}, got)
		})
	}
}
