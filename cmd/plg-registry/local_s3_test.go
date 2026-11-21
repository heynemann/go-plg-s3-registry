package main

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestLocalS3RefusesRedirect(t *testing.T) {
	var redirected atomic.Bool
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		redirected.Store(true)
		w.WriteHeader(http.StatusOK)
	}))
	defer other.Close()
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL, http.StatusTemporaryRedirect)
	}))
	defer origin.Close()

	r := &options{endpoint: origin.URL, registry: "demo", bucket: "test-publication", region: "us-east-1", output: "json"}
	client, _, err := r.connect(t.Context())
	require.NoError(t, err)
	_, err = client.Inspect(t.Context(), "eligibility", "v1.0.0", "")
	require.Error(t, err)
	require.False(t, redirected.Load(), "local-mode client must not follow cross-origin redirects")
}
