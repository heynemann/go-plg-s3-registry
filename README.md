# go-plg-s3-registry

An S3-backed release and rollout registry for [go-plg](https://github.com/heynemann/go-plg). The control plane is the `plg-registry` CLI and a protected execution workflow. The data plane is the `dataplane` Go SDK, which reads the host's environment bucket and invokes exact, verified plugin digests. There is no registry HTTP server, and go-plg does not import or configure the registry. See the [lifecycle spec](https://github.com/heynemann/go-plg-s3-registry/issues/1) and [operations guide](docs/operations.md).

**Release status:** [`v0.1.1` developer preview](docs/releases/v0.1.1.md). Use it with Floci and synthetic data. Live AWS production conformance is deferred; see [compatibility, supported versions and upgrades](docs/compatibility.md).

## Install

With Go 1.27.3:

```sh
go install github.com/heynemann/go-plg-s3-registry/cmd/plg-registry@v0.1.1
plg-registry --help
```

Run the installed binary from `GOBIN`, or from `$(go env GOPATH)/bin` if `GOBIN` is unset. Add the directory to `PATH` for the second command. In a Go host project, use `go get github.com/heynemann/go-plg-s3-registry/dataplane@v0.1.1` and confirm your host uses the [tested go-plg revision](docs/compatibility.md).

## Quickstart: local rewards rollout

Check out the same tag to run the example. It needs Git, Bash, Docker, curl 7.75.0+, jq, and OpenSSL in addition to Go:

```sh
git clone --branch v0.1.1 https://github.com/heynemann/go-plg-s3-registry.git
cd go-plg-s3-registry
./examples/rewards/run-demo.sh
```

The [rewards walkthrough](examples/rewards/README.md) publishes two Lua releases to local Floci, warms the upgrade at 0%, rolls it out to 25% of the EU audience, then shows how rollback and quarantine affect persisted retries. The HTTP API belongs to the example app, which uses only local fixtures and stores its ledger in SQLite. The registry exposes no HTTP API, and the demo never contacts live AWS.

## Build and test

Requires Go 1.27.3, Git, and Docker for integration tests.

```sh
go build ./cmd/plg-registry
go test -race -tags integration ./...
```

The integration suite starts isolated, digest-pinned Floci containers, packs real Lua plugins and exercises two independently configured go-plg hosts. It checks signed publication, approval and promotion, warming at 0%, targeted rollout, persisted retries, containment, expiry and recovered authority. It uses local keys and no AWS credentials. [Live AWS conformance](https://github.com/heynemann/go-plg-s3-registry/issues/15) is separate and deferred.

## Author a plugin

For this checkout, install the author CLI at the same go-plg version the host SDK uses:

```sh
go install github.com/heynemann/go-plg/cmd/plg@v0.1.0
```

From your author repository, use `plg init -lang lua -implements '<package>.<Interface>@<version>' <directory>` with your published contract. Implement the scaffold, add method cases under the plugin's `tests` directory, and run `plg validate <directory>`. Validation prints failing steps and cases. Commit the plugin and its tests before publishing. Run `plg pack -o /path/outside/author-repo <directory>`; pack validates and runs the tests itself, then writes a `.plg`. The registry requires a clean source revision and at least one passing author test in pack's report. Don't publish a working-tree build.

## Register, publish, inspect

Administrative onboarding reserves the plugin ID with owner, on-call route, HTTPS runbook, author repository, pinned reusable workflow, and its registered P-256 public key. Use `plg-registry plugin onboard --help` for arguments. A candidate's own `plugin.yaml` cannot change that binding. Repeat with the same binding to recover an interrupted onboarding response.

Call the [reusable publish workflow](.github/workflows/publish-plugin.yml) pinned to a reviewed registry commit. Grant the caller `contents: read` and `id-token: write`; the reusable workflow runs author code in a separate pack job without OIDC permission. The publish job downloads that job's artifact, uses the pinned registry source, and signs using short-lived AWS credentials. It does not execute author code. Pass the target registry, bucket and account, plugin ID, immutable version, directory, and the registered publisher role and key. Configure the author workflow to run on a protected ref only.

The deployment trust boundary is **IAM plus the registered signing key**, not a reported `GITHUB_*` environment variable:

- Use a dedicated asymmetric KMS `ECC_NIST_P256` signing key for each registered publisher binding. Register the exact key ARN and its public key; never reuse the key for another plugin or workflow. Give the publishing role `kms:Sign` only on its registered key. The CLI checks the signature against the stored key before writing.
- Configure [GitHub OIDC and AWS STS](https://docs.github.com/en/actions/how-tos/secure-your-work/security-harden-deployments/oidc-in-aws) with an exact audience and subject. Customize the subject to bind the immutable author repository identity, the protected ref context, and the exact reusable `job_workflow_ref` pinned to its commit. Use that subject in the AWS trust policy; a generic repository or environment subject alone is not a workflow binding.
- The administrator creates the plugin's index and immutable registration snapshots. The publisher can read those snapshots, conditionally stage signed releases and artifacts, and conditionally update only its own publication index. Enforce the matching write preconditions and no deletes in bucket policy; never give that role write access to registration snapshots or environment buckets. Inspection reads by exact key and requires no prefix listing.

Example read-only inspection (uses AWS's normal credential discovery):

```sh
./plg-registry --registry rewards --bucket example-releases --bucket-owner 123456789012 \
  --region us-east-1 --output json release inspect --plugin eligibility --version v1.0.0
```

Use `--digest sha256:<64 lowercase hex digits>` instead of `--version` to find all published versions for an exact archive. Inspection verifies signed metadata against the administrator's binding; it does not download or load the artifacts. AWS `--bucket-owner` is mandatory. For local development only, use `--endpoint http://127.0.0.1:<port>` instead of `--bucket-owner`, `--key-id local:<name>`, and a P-256 PKCS#8 PEM `--local-key` on publish. That mode uses dummy loopback credentials and an administrator-supplied PKIX PEM public key. See the integration test for a complete local example.

`--output json` emits versioned records on stdout; failures go to stderr. Exit codes distinguish invalid input (2), unauthorized publisher (3), immutable conflict (4), missing record (5), and invalid evidence in storage (6). Other failures exit 1. A successful publication is not an activation or evidence of host readiness.

## Control rollouts

Use `rollout preview` on synthetic inputs without a bucket or cloud credentials. Propose a plan for an exact digest and approve it separately. The [protected workflow](.github/workflows/control-apply.yml) applies reviewed requests against the exact expected revision. `status` reports committed state and freshness; `history` reports the applied chain, not orphaned proposals or losing writes. See [bootstrap, rollout, and recovery instructions](docs/operations.md).

Publishing does not serve a plugin. First activation serves only after local verification, a live freshness proof, and a warmed runtime. Upgrades begin at 0%; `finish` retains the approved audience. A global default change needs explicit authorization. Rollback preserves receipts; quarantine blocks new calls even for existing pins on hosts that have seen it.

## Integrate a host

For Lua plugins, link `_ "github.com/heynemann/go-plg/guest/lua"` and use `dataplane.Attach[YourContract](ctx, nil, config, plg.WithLuaPlugins())` to register an SDK-owned go-plg container. Configure a read-only S3 client, scope and bucket owner, deployment-pinned verification keys, explicit unavailable behavior, capability ceilings, and the retry horizon. `Sync` bootstraps one revision; `Run` polls until canceled. Check `Status` for readiness and close the host on shutdown.

Call `Select` with an opaque stable application key and allowlisted attributes. Persist the returned receipt in your operation store **before** side effects. Call `Invoke` with it and a bounded context; on retry, read the same receipt and call `InvokeRetry`. Never reselect to rescue a blocked pin. The registry does not store business operations, deliveries or idempotency keys. This pattern is exercised in the integration test across independent hosts.

Use [the telemetry contract and dashboard queries](docs/observability/dashboard.md) with your existing OpenTelemetry exporters. Committed intent, effective host state, first invocations, and pinned retries are different signals.
