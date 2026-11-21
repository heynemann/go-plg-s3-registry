//go:build integration

package main_test

import (
	"bufio"
	"context"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/bytedance/sonic"
	"github.com/stretchr/testify/require"

	"github.com/heynemann/go-plg-s3-registry/internal/rollout"
	"github.com/heynemann/go-plg-s3-registry/internal/target"
)

func TestRewardsExample(t *testing.T) {
	f := startLifecycle(t)
	repo, err := filepath.Abs("../..")
	require.NoError(t, err)
	binary, db := filepath.Join(f.dir, "rewards"), filepath.Join(f.dir, "deliveries.sqlite")
	run(t, repo, nil, "go", "build", "-race", "-o", binary, "./examples/rewards/cmd/rewards")
	host := f.startRewards(binary, db)
	host.do("GET", "/readyz", "", http.StatusServiceUnavailable)

	plan, approval := f.approve(rollout.Plan{Scope: f.deployment.Scope, Candidate: f.first, Unavailable: "hold"})
	initial := f.execute("decider", "rollout", "activate", rollout.Command{ID: "install-v1", PlanID: plan, ApprovalID: approval, Reason: "activate baseline"})
	f.renew()
	host.ready(initial.DecisionID)
	const eu = `{"subject":"user-2","region":"EU","tier":"silver"}`
	const us = `{"subject":"user-2","region":"US","tier":"silver"}`
	require.Contains(t, host.do("PUT", "/v1/deliveries/invalid", `{"subject":"user-2","region":"EU"}`, 400).media, "application/problem+json")
	host.do("GET", "/v1/deliveries/invalid", "", http.StatusNotFound)
	host.do("POST", "/v1/deliveries/invalid/attempt", "", http.StatusNotFound)
	host.delivery("PUT", "first", eu, 201, "pending", f.first.Digest, 0)
	host.delivery("POST", "first/attempt", "", 200, "ineligible", f.first.Digest, 0)

	evidence := []string{"https://example.com/adoption"}
	plan, approval = f.approve(rollout.Plan{Scope: f.deployment.Scope, Candidate: f.second, Baseline: f.first, Unavailable: "hold",
		Target: target.Spec{Version: 1, Expression: `region == "EU"`, Attributes: map[string]string{"region": "string"}, Seed: strings.Repeat("0", 64)},
		Rungs:  []uint16{2500, 10000}, Evidence: evidence, StopConditions: []string{"incorrect delivery"}})
	warm := f.execute("decider", "rollout", "activate", rollout.Command{ID: "warm-v2", Expected: initial.DecisionID, PlanID: plan, ApprovalID: approval, Reason: "warm at zero"})
	f.renew()
	host.ready(warm.DecisionID)
	host.delivery("PUT", "zero-rung", eu, 201, "pending", f.first.Digest, 0)
	host.delivery("POST", "zero-rung/attempt", "", 200, "ineligible", f.first.Digest, 0)
	advanced := f.execute("decider", "rollout", "advance", rollout.Command{ID: "ramp-v2", Expected: warm.DecisionID,
		ApprovalID: approval, Rung: 2500, Reason: "verified both versions warm", Evidence: evidence})
	f.renew()
	host.ready(advanced.DecisionID)
	host.delivery("PUT", "outside-cohort", us, 201, "pending", f.first.Digest, 0)
	host.delivery("POST", "outside-cohort/attempt", "", 200, "ineligible", f.first.Digest, 0)
	host.delivery("PUT", "retry-after-restart", eu, 201, "pending", f.second.Digest, 0)
	host.delivery("PUT", "quarantined", eu, 201, "pending", f.second.Digest, 0)
	conflict := host.do("PUT", "/v1/deliveries/retry-after-restart", us, http.StatusConflict)
	require.Contains(t, conflict.media, "application/problem+json")

	rolled := f.execute("responder", "rollout", "rollback", rollout.Command{ID: "rollback-v2", Expected: advanced.DecisionID, Reason: "return new deliveries to baseline", Incident: "demo-1"})
	f.renew()
	host.stop()
	host = f.startRewards(binary, db)
	host.ready(rolled.DecisionID)
	host.delivery("GET", "first", "", 200, "ineligible", f.first.Digest, 0)
	host.delivery("GET", "retry-after-restart", "", 200, "pending", f.second.Digest, 0)
	host.delivery("PUT", "retry-after-restart", eu, 200, "pending", f.second.Digest, 0)
	peer := f.startRewards(binary, db)
	peer.ready(rolled.DecisionID)
	raceRewardsAttempts(t, host, peer)
	host.delivery("GET", "retry-after-restart", "", 200, "delivered", f.second.Digest, 100)
	peer.stop()
	host.delivery("PUT", "after-rollback", eu, 201, "pending", f.first.Digest, 0)
	host.delivery("POST", "after-rollback/attempt", "", 200, "ineligible", f.first.Digest, 0)

	denied := f.execute("responder", "release", "quarantine", rollout.Command{ID: "quarantine-v2", Expected: rolled.DecisionID,
		Reason: "block in-flight work from starting on v2", Incident: "demo-2", Digest: f.second.Digest})
	f.renew()
	host.ready(denied.DecisionID)
	response := host.do("POST", "/v1/deliveries/quarantined/attempt", "", http.StatusServiceUnavailable)
	require.Contains(t, response.media, "application/problem+json")
	problem := decodeJSON[struct {
		Type      string `json:"type"`
		RequestID string `json:"request_id"`
	}](t, response.body)
	require.Equal(t, "urn:rewards:quarantined", problem.Type)
	require.NotEmpty(t, problem.RequestID)
	host.delivery("GET", "quarantined", "", 200, "pending", f.second.Digest, 0)
	// A response replay must not invoke a quarantined plugin or create a second award.
	host.delivery("POST", "retry-after-restart/attempt", "", 200, "delivered", f.second.Digest, 100)
}

func raceRewardsAttempts(t *testing.T, hosts ...*rewardsProcess) {
	t.Helper()
	type result struct {
		httpResult
		err error
	}
	start := make(chan struct{})
	results := make(chan result, len(hosts))
	for _, host := range hosts {
		go func() {
			<-start
			res, err := host.request(t.Context(), "POST", "/v1/deliveries/retry-after-restart/attempt", "")
			results <- result{res, err}
		}()
	}
	close(start)
	first := <-results
	require.NoError(t, first.err)
	require.Equal(t, http.StatusOK, first.status, "%s", first.body)
	for i := 1; i < len(hosts); i++ {
		next := <-results
		require.NoError(t, next.err)
		require.Equal(t, http.StatusOK, next.status, "%s", next.body)
		require.JSONEq(t, string(first.body), string(next.body), "competing callers must observe the same award")
	}
}

type rewardsProcess struct {
	t      *testing.T
	base   string
	stop   func()
	client http.Client
}

func (f *lifecycle) startRewards(binary, db string) *rewardsProcess {
	f.t.Helper()
	cmd := exec.Command(binary, "--config", f.config, "--endpoint", f.endpoint, "--db", db,
		"--listen", "127.0.0.1:0", "--poll-interval", "100ms")
	cmd.Dir = f.dir
	stdout, err := cmd.StdoutPipe()
	require.NoError(f.t, err)
	cmd.Stderr = os.Stderr
	require.NoError(f.t, cmd.Start())
	started, done := make(chan string, 1), make(chan struct{})
	var waitErr error
	go func() {
		scan := bufio.NewScanner(stdout)
		for scan.Scan() {
			if url, ok := strings.CutPrefix(scan.Text(), "listening "); ok {
				select {
				case started <- url:
				default:
				}
			}
		}
		waitErr = cmd.Wait()
		close(done)
	}()
	stopped := false
	stop := func() {
		if stopped {
			return
		}
		stopped = true
		_ = cmd.Process.Signal(syscall.SIGTERM)
		select {
		case <-done:
			require.NoError(f.t, waitErr, "rewards shutdown")
		case <-time.After(15 * time.Second):
			_ = cmd.Process.Kill()
			f.t.Error("rewards did not stop on SIGTERM")
		}
	}
	f.t.Cleanup(stop)
	select {
	case url := <-started:
		return &rewardsProcess{t: f.t, base: url, stop: stop, client: http.Client{Timeout: 5 * time.Second}}
	case <-done:
		f.t.Fatalf("rewards exited before listening: %v", waitErr)
	case <-time.After(15 * time.Second):
		f.t.Fatal("rewards did not start listening")
	}
	return nil
}

type httpResult struct {
	status int
	media  string
	body   []byte
}

func (h *rewardsProcess) request(ctx context.Context, method, path, body string) (httpResult, error) {
	req, err := http.NewRequestWithContext(ctx, method, h.base+path, strings.NewReader(body))
	if err != nil {
		return httpResult{}, err
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := h.client.Do(req)
	if err != nil {
		return httpResult{}, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	return httpResult{resp.StatusCode, resp.Header.Get("Content-Type"), data}, err
}

func (h *rewardsProcess) ready(decision string) {
	h.t.Helper()
	ctx, cancel := context.WithTimeout(h.t.Context(), 15*time.Second)
	defer cancel()
	ticks := time.NewTicker(50 * time.Millisecond)
	defer ticks.Stop()
	for {
		resp, err := h.request(ctx, "GET", "/readyz", "")
		var status struct {
			Ready     bool `json:"ready"`
			Effective struct {
				Decision string `json:"decision"`
			} `json:"effective"`
		}
		if err == nil && resp.status == 200 && sonic.ConfigStd.Unmarshal(resp.body, &status) == nil && status.Ready && status.Effective.Decision == decision {
			return
		}
		select {
		case <-ticks.C:
		case <-ctx.Done():
			h.t.Fatalf("rewards did not adopt %s: HTTP %d, %s (%v)", decision, resp.status, resp.body, err)
		}
	}
}

func (h *rewardsProcess) do(method, path, body string, status int) httpResult {
	h.t.Helper()
	result, err := h.request(h.t.Context(), method, path, body)
	require.NoError(h.t, err)
	require.Equal(h.t, status, result.status, "%s %s: %s", method, path, result.body)
	return result
}

func (h *rewardsProcess) delivery(method, suffix, body string, code int, status, digest string, amount int) {
	h.t.Helper()
	result := h.do(method, "/v1/deliveries/"+suffix, body, code)
	data := decodeJSON[struct {
		ID     string `json:"id"`
		Status string `json:"status"`
		Digest string `json:"plugin_digest"`
		Amount int    `json:"amount_cents"`
	}](h.t, result.body)
	id, _, _ := strings.Cut(suffix, "/")
	require.Equal(h.t, id, data.ID)
	require.Equal(h.t, status, data.Status, "%s %s", method, suffix)
	require.Equal(h.t, digest, data.Digest)
	require.Equal(h.t, amount, data.Amount)
}
