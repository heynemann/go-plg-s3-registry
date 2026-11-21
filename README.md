# go-plg-s3-registry

An S3-backed release registry for [go-plg](https://github.com/heynemann/go-plg). The current slice reserves plugin identities, publishes signed releases, and verifies release metadata on inspection. Publishing never creates serving state. See [the lifecycle plan](https://github.com/heynemann/go-plg-s3-registry/issues/1) and [technical contracts](docs/specs/control-plane.md).

## Build and test

Requires Go 1.27.3, Git, and Docker for integration tests.

```sh
go build ./cmd/plg-registry
go test -race -tags integration ./...
```

The integration test starts a digest-pinned Floci container, builds both CLIs, scaffolds and packs a real Lua plugin, publishes it, and inspects its signed release. It uses local keys and no AWS credentials. Live AWS conformance is intentionally not run at this stage.

## Author a plugin

Use the pinned go-plg tool from this module to install the author CLI:

```sh
go install github.com/heynemann/go-plg/cmd/plg@v0.0.0-20261110221856-eed62cdec1bc
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
