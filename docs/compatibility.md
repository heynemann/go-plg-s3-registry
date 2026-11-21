# Compatibility and support

**`v0.1.1` is a developer preview, not a production-ready `v1.0.0`.** Use disposable Floci environments and synthetic workloads. The release tests cover the published CLI, the registry lifecycle and real rewards HTTP invocations. The separate [AWS production conformance gate (#15)](https://github.com/heynemann/go-plg-s3-registry/issues/15) has not been run. AWS and GitHub integrations are included for evaluation; the preview does not certify AWS IAM, KMS, S3 durability or recovery, or support arbitrary S3-compatible providers.

| Surface | `v0.1.1` expectation |
| --- | --- |
| Go toolchain and go-plg | Go 1.27, tested with Go 1.27.3. Both the author CLI and host runtime are tested with `github.com/heynemann/go-plg` at `v0.0.0-20261110221856-eed62cdec1bc`. Other revisions have not been validated. Check the version selected by your host module, not just the version declared here. |
| CLI and SDK | Pin `plg-registry` and the `dataplane` import to the same registry release. Use `--output json` for automation. CLI flags, JSON results, exit codes and the Go API may change before v1. |
| Stored state | The `v1/` S3 prefix and version-1 signed records, targeting and receipts are format versions, **not** a stable SemVer promise. In one preview environment use the matching CLI, workflows, and hosts. There is no cross-release migration or downgrade guarantee. |
| Rollout capacity | Keep preview environments small. Publication indexes and signed records have a 1 MiB record limit. Command deduplication and cold historical receipt admission can walk applied history. Large or long-lived registries are not yet qualified. |
| Operational integration | The Floci suite runs the public CLI with separate local keys, not the hosted protected workflow. Capability-ceiling comparison is a manual pre-approval check; correctness alerts start with the host owner and require triage. |

## Trying a newer preview

1. Keep the old binaries, workflow revision, public trust and data together. Stop new assignments and let pending pinned work finish, or hold it under the original environment and policy. Don't send an old pending receipt to a new environment or silently repin it.
2. Read the new release notes before switching. Unless they explicitly document a supported migration, try the new preview in fresh buckets with a matching CLI, SDK, workflows and deployment configuration. Rebuild the disposable rewards demo from that tag.
3. Back up operation storage independently of S3. Restoring objects is not authorization to serve; the [recovery runbook](operations.md#recovery) requires an independently corroborated checkpoint and fenced authority.

A stable release requires a repeatable least-privilege AWS deployment and conformance run, supported-version and upgrade tests for persisted state and receipts, and documented history/retention limits. A passing local walkthrough is evidence of the lifecycle, not a substitute for those gates.
