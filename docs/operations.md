# Operating the registry

The registry has no management server. Run `plg-registry` locally for authoring, preview and inspection; run state-changing production commands in the protected control workflow. The host integrates the Go data plane and reads its own environment bucket with a read-only role. Neither publishing nor writing rollout records directly is an invocation API.

## Bootstrap trust

Configure a publication bucket and a separate production AWS account, bucket, encryption key and role boundary. The deployment pins expected bucket owners and regional endpoints. Enable bucket versioning, encryption, access logging and retention compatible with the longest host retry horizon. Run reconciliation from the current primary, not a replica or a CDN. Give hosts read-only access to their environment, not to the publication source or to signing keys. Keep a copy of the authority epoch and verified applied checkpoint in independent deployment/audit storage.

| Principal | Allowed work |
| --- | --- |
| Author pack job | Build and test clean source; no production, registry-write or signing credentials. |
| Trusted publication workflow | Read the admin-owned publisher binding, sign with the plugin-scoped key, conditionally stage release/artifact records and commit the publication index. The workflow is pinned by OIDC trust; do not share its role with arbitrary author jobs. |
| Publisher trust administrator | Reserve identity, rotate or suspend a binding using the expected policy digest. Preserve immutable historical bindings. Do not grant serving-state writes. |
| Proposer and approver | Sign proposals or exact approvals with separate purpose-scoped keys and principals. Read the release and applied history needed for review; no serving-head writes. |
| Protected decider | Verify commands and approvals, promote verified bytes from the publication account, and conditionally write the environment head. Cannot mint its own approval or approve quarantine restoration. |
| Incident responder | Sign pause, rollback and quarantine transitions only. Enforce restrictions in the protected executor and verify allowed signature purposes on readers. It cannot restore or increase traffic. |
| Renewer | Read the authoritative head and write only that head's signed freshness record, using a separate key. No writes to head, release admission or deny state. |
| Recoverer | After external checkpoint reconciliation and fencing, establish a new epoch with its own trusted bootstrap. Never make a restored epoch authoritative just because the objects exist. |

S3 permissions are necessary but not sufficient: state-changing roles are available only to reviewed, pinned executors, not directly to human CLI sessions. Scope each key and OIDC trust to the purpose, immutable repository identity, workflow revision and approved environment. Enforce `If-None-Match: *` for immutable writes, require conditional writes for indexes and heads, and deny ordinary deletes/version deletion on protected prefixes. Do not grant a raw S3 writer both the storage and signing privileges for distinct purposes. Keep signer configuration and deployment binding under protected review. Identities in deployment trust are authorized principals (including IAM roles); an operator-supplied string is not identity evidence. Map privileged workflow runs to authenticated initiating/approving humans through the provider's audited change/approval records and retain those links outside S3. Do not infer human identity from a shared role ARN.

### Configure the control workflow

In a protected operator checkout, the workflow reads `control/deployments/<deployment>.json` and `control/requests/<deployment>/<operation>/<request>.json` from the exact reviewed commit. Protect those paths, the executor, and workflow with code owners. Configure GitHub environments `control-proposer`, `control-approver`, `control-decider`, `control-responder`, `control-renewer`, `control-recoverer`, and `control-publisher-admin` with reviewed default-branch deployments and required reviewers; prevent self-review and administrative bypass. Keep reviewers for approval independent of proposal and execution. Set `PLG_CONTROL_ROLE`, `PLG_CONTROL_ACCOUNT`, and `PLG_CONTROL_REGION` in each environment. Use the pinned role even when multiple deployments are managed; if roles or isolation boundaries differ, use distinct protected workflow repositories/environments and pin the corresponding bindings.

A deployment JSON file is not a credential. It pins these fields:

| Field | Contract |
| --- | --- |
| `schema_version` and `scope` | Schema `1`; `scope` contains `registry`, `environment`, `plugin`, and the active `epoch`. |
| `destination`, `publication` | Distinct `bucket`, expected account `owner`, and `region`; production destination in a separate AWS account. |
| `max_lease`, `max_clock_skew` | Go durations; choose the maximum acceptable disconnected exposure and a smaller clock-skew allowance. |
| `authorities` | Entries with `role`, `key_id` (exact KMS key ARN), base64 DER `public_key_pkix`, exact `aws_role_arn`, and immutable `aws_role_id`; publisher administration has a distinct AWS role and need not have a signing key. |
| `github` | Repository `owner/name`, immutable `repository_id`, and reviewed default `branch`; required in AWS mode. |
| `recovery` | Optional independently recorded `{scope,generation,decision}` checkpoint from before an epoch move. |

Manual AWS mutations verify the short-lived STS role, its workflow run and the independent GitHub environment review. Signed proposal, approval and decision records include the provider's repository/run/commit and immutable initiator and reviewer IDs. Approval cannot reuse a proposer or executor identity as its reviewer. Use a new workflow dispatch after a lost response, with the **same command ID and request**; reruns cannot reuse a prior run's environment review.

Schedule `plg-registry --config <deployment.json> freshness renew --duration <lease>` with a separately pinned renewer workload role at a cadence well below the lease window. It must read the active primary and run with monitored clocks. This role uses short-lived AWS credentials and does not need a GitHub token or a human approval for each timed renewal. The protected workflow also supports manual renewal. Following a committed change, renew the new head before treating it as serving; the previous head's proof does not authorize it.

For local development, set `--endpoint http://127.0.0.1:<port>`, omit account owners and `github`, and set each `key_id` to a separate `local:<name>` P-256 key. Omit AWS role fields. Use `--local-key <PKCS8.pem>` only on commands that need that role; verification uses the deployment's public keys.

### Author and review requests

- Run `plg-registry --output json rollout preview --plan <plan.json> --subject <synthetic-id> --attrs <synthetic-context.json> --rung <basis-points>` without cloud credentials. See the [targeting spec](specs/data-plane.md#selection-and-receipt-semantics) for field types and stable vectors.
- Use `rollout propose --plan` to submit a plan (`scope`, exact `candidate`, `unavailable`; upgrades also need `baseline`, typed `target`, `rungs`, `evidence`, and `stop_conditions`). Use `rollout approve --plan-id` on the returned plan digest. A command JSON carries `id`, `expected` (the exact current decision digest; empty only for first activation), `reason`, and action-specific fields described by `--help`. The command group fixes its operation.
- Run `plg-registry --config <deployment.json> --output json status` or `history` to recover `decision.decision_id` or `decisions[].decision_id`. Read the desired state and use the [observability dashboard](observability/dashboard.md) to verify adoption and exposure separately.

## Safe operations

1. Inspect the exact version, digest, evidence and requested manifest capabilities. Agree the host's policy and unavailable behavior. Propose and separately approve the exact plan.
2. For the first launch, activate at full exposure per ready host. An upgrade must warm both versions at 0%. If host readiness has not converged, stop before advancing. A lagging host may use a still-authorized, unexpired plan, so desired state does not prove actual exposure.
3. Review verified host coverage, actual invocation lanes and host-owned correctness signals. Record links to that evidence and a reason when manually advancing a rung. The final rung does not widen the approved audience. A default change is separate.
4. Roll back to narrow new selection without changing persisted receipts. Quarantine to deny new calls including pinned retries, even on hosts whose next candidate failed to load. Already-admitted calls may finish. Report which hosts observed the deny and which disconnected hosts can still start work until expiry. Hold or reject blocked work; never repin automatically.
5. Restore a digest only with independent fresh approval against the current quarantine revision. Clearing a deny does not select that digest for new work. If desired, propose a separate activation. Routine publisher rotation is not a quarantine. During suspected compromise, suspend publication first and assess the reported admitted digests before quarantining them in each affected environment.

When a command times out, inspect the applied decision chain for its command ID and original expected revision. Retrying identical input can recover the result; do not rebase a failed or competing command onto newer desired state without reviewing it. Artifact and decision staging may leave unreferenced objects; a staged signed decision is not evidence of application.

## Recovery

Fence normal old-epoch writers and renewers before choosing a recovery checkpoint. Use independently retained audit and version evidence to establish the latest **applied** old-epoch head, including its deny set. Quarantine old credentials even if storage is still readable. Restore the exact old head and its verified history, release metadata and artifacts into the destination. Configure the new epoch and the externally verified old head identity in deployment trust; do not obtain the expected identity from the backup itself. If the checkpoint or decision chain cannot be verified, stay unavailable. After authorized recovery publishes the first new-epoch generation, issue fresh proofs for that head and deploy hosts pinned to the new epoch. An old scoped plan may resume its exact already-approved routing but cannot advance under an old-epoch approval; contain/rollback before starting another upgrade. Old stored receipts still require proof that the selection is on the recovered applied chain, remains callable within the retry horizon, and is not denied.

See [the S3 protocol](specs/s3-protocol.md) for the wire and consistency rules. Local verification uses Floci only. AWS production deployment still requires the separate IAM/KMS and S3 conformance checks before relying on these boundaries; the deferred check is [#15](https://github.com/heynemann/go-plg-s3-registry/issues/15).
