//go:build integration

package main_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	"go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"

	"github.com/heynemann/go-plg-s3-registry/dataplane"
)

type telemetryFixture struct {
	t       *testing.T
	readers map[string]*metric.ManualReader
	tracer  *trace.TracerProvider
	spans   *tracetest.SpanRecorder
}

func newTelemetry(t *testing.T) *telemetryFixture {
	t.Helper()
	s := tracetest.NewSpanRecorder()
	p := trace.NewTracerProvider(trace.WithSpanProcessor(s))
	t.Cleanup(func() { require.NoError(t, p.Shutdown(context.Background())) })
	return &telemetryFixture{t: t, readers: make(map[string]*metric.ManualReader), tracer: p, spans: s}
}

func (f *telemetryFixture) config(host string) dataplane.Telemetry {
	reader := metric.NewManualReader()
	meter := metric.NewMeterProvider(metric.WithReader(reader))
	f.readers[host] = reader
	f.t.Cleanup(func() { require.NoError(f.t, meter.Shutdown(context.Background())) })
	return dataplane.Telemetry{MeterProvider: meter, TracerProvider: f.tracer, HostID: host, HostOwner: "app-ops", RegistryOwner: "registry-ops"}
}

func (f *telemetryFixture) verify(t *testing.T) {
	t.Helper()
	counts := map[string]int64{}
	gauges := map[string]int64{}
	traced := false
	for host, reader := range f.readers {
		var collection metricdata.ResourceMetrics
		require.NoError(t, reader.Collect(t.Context(), &collection))
		for _, scope := range collection.ScopeMetrics {
			for _, m := range scope.Metrics {
				switch points := m.Data.(type) {
				case metricdata.Sum[int64]:
					for _, p := range points.DataPoints {
						if m.Name == "registry.host.operations" {
							counts[label(p.Attributes, "operation")+"/"+label(p.Attributes, "lane")+"/"+label(p.Attributes, "outcome")] += p.Value
						}
						for _, a := range p.Attributes.ToSlice() {
							require.Contains(t, []attribute.Key{"registry", "environment", "plugin", "operation", "lane", "outcome", "kind", "state"}, a.Key)
						}
					}
				case metricdata.Gauge[int64]:
					if m.Name != "registry.host.revision" {
						continue
					}
					for _, p := range points.DataPoints {
						gauges[host+"/"+label(p.Attributes, "stage")] = p.Value
					}
				}
			}
		}
	}
	require.Positive(t, counts["invoke/candidate/ok"])
	require.Positive(t, counts["correctness/candidate/incorrect"])
	require.Positive(t, counts["invoke_retry/candidate/quarantined"])
	require.Positive(t, counts["invoke_retry/candidate/stale"])
	require.Greater(t, gauges["host-b/observed"], gauges["host-b/effective"])
	for _, span := range f.spans.Ended() {
		a := attribute.NewSet(span.Attributes()...)
		if span.Name() == "registry.invoke" && label(a, "registry.lane") == "candidate" && label(a, "registry.outcome") == "ok" {
			require.Equal(t, "rewards", label(a, "registry.plugin.owner"))
			require.Equal(t, "rewards-ops", label(a, "registry.plugin.on_call"))
			require.Equal(t, "https://example.com/runbooks/rewards", label(a, "registry.plugin.runbook"))
			require.Equal(t, "host-a", label(a, "registry.host.id"))
			require.Equal(t, "app-ops", label(a, "registry.host.owner"))
			require.Equal(t, "registry-ops", label(a, "registry.operations.owner"))
			require.NotEmpty(t, label(a, "registry.decision"))
			require.NotEmpty(t, label(a, "registry.digest"))
			traced = true
		}
		for _, value := range a.ToSlice() {
			require.NotEqual(t, "user-2", value.Value.Emit(), "target subjects must not be exported")
		}
	}
	require.True(t, traced, "expected a trace of an admitted candidate call")
}

func label(a attribute.Set, key string) string {
	value, _ := a.Value(attribute.Key(key))
	return value.AsString()
}
