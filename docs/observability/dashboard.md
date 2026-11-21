# Rollout dashboard and alert integration

Give each host process an explicit OpenTelemetry meter and tracer provider. Export one metric stream per host process (for Prometheus, preserve a unique scrape `instance`; for OTLP, preserve an equivalent `service.instance.id` resource identity). Keep `registry`, `environment`, and `plugin` dimension values on an inventory-backed allowlist. Do not attach host IDs, digests, decisions, subject keys, or raw attribute values as SDK metric dimensions. If exporting go-plg runtime metrics too, drop the digest-bearing runtime registration key or map it to the same bounded plugin inventory. Exporters and data retention belong to the host owner.

Use the [reference Prometheus rules](prometheus.yml) with exporters that translate OTLP instrument names to Prometheus names using underscore separators, `_total` for counters, and `_seconds` for durations. Preserve the unitless gauge names as shown. Compare only live, distinct reporters. Every dashboard row is grouped by `registry`, `environment`, `plugin`; add `instance` only for host diagnosis. Treat an empty series, missing instance, or absent call sample as **unknown**, not zero exposure or success.

| Panel | Series or PromQL |
| --- | --- |
| Desired, observed, effective generations | `registry_host_revision`, split by `stage`; cross-check desired against `plg-registry status` for the primary. The SDK's desired generation is the latest this host observed, not a global value. Compare reporting hosts by instance and use `registry:observed_generation:max` against `registry:effective_generation:min`. |
| Fresh/ready coverage | `sum by (registry,environment,plugin,state) (registry_host_state)` divided by the number of expected hosts from deployment inventory, not by just the healthy reporters. Also show reporting vs. expected separately. Page on missing fleet data using your existing inventory or failed-scrape alert. |
| Candidate share, first invocations only | `registry:initial_candidate_share:ratio5m`. It is the observed share of admitted first invocations, not the configured percentage or share of unique users. On partial telemetry or no invocations, show unknown. |
| First calls, pinned retries, errors, timeouts | `sum by (registry,environment,plugin,operation,lane,outcome) (rate(registry_host_operations_total{operation=~"invoke\|invoke_retry"}[5m]))`; do not combine retry traffic with first invocations. |
| p95 duration, seconds | `histogram_quantile(0.95, sum by (le,registry,environment,plugin,operation,lane) (rate(registry_host_duration_seconds_bucket{operation=~"invoke\|invoke_retry\|load\|sync"}[5m])))`. Interpret alongside counts and outcomes. |
| Assignment quality | `sum by (registry,environment,plugin,lane,outcome) (rate(registry_host_operations_total{operation="select"}[5m]))`; distinguish `targeting_error` from `non_match`. |
| Warm/admission failures | `sum by (registry,environment,plugin,operation,outcome) (rate(registry_host_operations_total{operation=~"sync\|load\|warm",outcome!="ok"}[5m]))`. A verified archive download does not prove that the runtime warmed it. |
| Pool and cache pressure | `registry_host_pressure`, split by `kind` and instance. Compare `in_use` with `instances`; show `waiting`, `cold_waiting`, `linear_memory_bytes` and `cache_bytes` separately. |
| Correctness | `sum by (registry,environment,plugin,lane,outcome) (increase(registry_host_operations_total{operation="correctness"}[5m]))`. The host explicitly reports `correct`, `incorrect` or `unknown`; missing reports are not correct outcomes. |

## Route an incident

Use an Alertmanager receiver or trusted routing service with a deployment-controlled mapping keyed by `(registry, environment, plugin, route)`. A `route: host` event goes to the host on-call, `route: plugin` to the registered plugin on-call, and `route: registry` to registry operations. A missing mapping routes to the registry operator rather than discarding the alert. Do not generate routes from guest inputs, arbitrary error strings, or the plugin archive's declared owner.

Group Alertmanager notifications by `registry`, `environment`, `plugin` and `route`; keep concurrent alerts for the same affected operation together without joining different owner routes. Include the relevant alert action and evidence window in the notification.

Follow the alert's action and correlate spans by scope, time, lane and operation. Registry invocation spans carry exact decision, digest and host identifiers, host/registry owner, and registry-verified plugin owner, on-call route and runbook on admitted calls. Compare requested and previous effective state without widening traffic. Quarantine a digest for containment; pause when evidence is incomplete. Telemetry does not grant authority, automatically advance rollout, or guarantee that every host saw a decision.

For a quarantine assessment, query traces for the exact `registry.digest` and group observed activity by environment and lane. In each configured environment compare that activity with the verified CLI `status` and `history`. Unobserved environments remain unknown; a deny in one environment does not authorize a write to another.
