# Registry control plane — v1 technical specification

Source: [lifecycle spec #1](https://github.com/heynemann/go-plg-s3-registry/issues/1). Applies to the standalone `github.com/heynemann/go-plg-s3-registry` module. See the [S3 handoff protocol](s3-protocol.md) and the [data plane](data-plane.md).

## API boundary

The **control plane authorizes what may run**: onboarding, publishing, promotion, approval, rollout, rollback, quarantine, freshness renewal and recovery. Its v1 API is a versioned CLI command contract and the request/result of a protected execution workflow. **There is no registry HTTP server in v1.** Use AWS S3 for the authoritative handoff. CLI clients may read authorized status; operator credentials do not write production state directly. Observability informs operations; it does not authorize changes.

If an adopter later needs a shared HTTP management endpoint, specify it separately. It must be an OpenAPI-first `/v1` façade over the same commands, not a second policy or storage authority. Apply the Go HTTP API conventions to that façade: OpenAPI 3.0.3, generated strict handlers, Fiber v3/fx, contract validation and RFC 9457 errors with request IDs. Do not introduce Fiber, OpenAPI, PostgreSQL, Redis or a serving endpoint solely to implement the v1 command contract.

## Command contract

`--output json` provides a versioned result on stdout; diagnostics go to stderr and never contain credentials, secrets or raw targeting inputs. Local preview does not require a write role. A workflow dispatch is only a submission; the executed CLI reports the committed result or an error. A committed decision is not evidence that hosts adopted it. See the [compatibility policy](../compatibility.md) for preview guarantees.

| Operation | Caller and request | Result / invariant |
| --- | --- | --- |
| `plugin onboard` | Registry administrator; stable plugin ID, verified team, on-call and runbook, allowed repositories and CI workflows | A reserved ID with versioned ownership and publisher policy. Artifact metadata is not proof of authority. |
| `release publish`, `release inspect` | Authorized CI publishes a packed archive, author-chosen version and verified build/test evidence; readers inspect by ID/version or exact digest | An immutable release binding. No activation. Retrying the identical publication returns the same release; reusing the version for a different manifest or bytes is a conflict. |
| `rollout preview`, `rollout propose` | Owner supplies environment, exact candidate release, baseline, predicate/schema version, seed, ordered rungs, checks and stop conditions | Preview runs the serving evaluator on synthetic inputs with match/bucket/decision and safe reason codes. Propose returns the immutable plan ID and content hash; it does not write active state. |
| `rollout approve` | Independent production approver; plan hash, plugin, environment, and approval evidence from a trusted identity/workflow integration | Approval binds that precise plan, not a release name. Changes outside it require new approval. |
| `rollout activate`, `rollout advance`, `rollout resume`, `rollout finish`, `rollout set-default` | Authorized operator submits command ID, expected revision, approval, reason and evidence references to the protected executor | Applies one allowed transition or returns a conflict/rejection. `finish` never widens targeting. `set-default` is a distinct authorized decision. |
| `rollout pause`, `rollout rollback`, `release quarantine` | Authorized on-call; expected revision, reason and incident reference | Narrow-only actions. Pause stops advancement. Rollback changes new assignments, not pins. Quarantine denies one plugin/digest throughout the environment, including pinned calls. |
| `release restore`, `publisher rotate`, `publisher suspend` | Fresh independent approval to clear quarantine; separate trust administrator for publisher changes | Clearing a deny entry does not activate or ramp the digest. Routine rotation preserves verifiably admitted artifacts; suspension blocks new publishes and lists affected digests for review. |
| `status`, `history` | Authorized reader, scoped to plugin/environment | `status` shows committed desired state and proof freshness; `history` follows the applied decision chain. Host adoption and actual traffic come from the host telemetry, not these commands. An unknown observation is not zero or ready. |
| `freshness renew`, `recovery reconcile` | Separate automated renewal authority; separately authorized recovery operator | Renew only current committed state. Recover by reconciling history and denies and fencing the old authority before issuing fresh proofs; no automatic failover. |

### Changes, approvals and retries

- Every applied command returns its command/decision ID, environment, plugin ID, previous and applied revisions, and whether the request was already applied. Status/history can resolve a lost response. Apply is separate from adoption and exposure; report these separately even at 100%.
- A mutation checks its expected revision, actor, policy, command-specific invariants and exact approval before the conditional write. Command IDs are scoped to plugin/environment; reuse with different input is a conflict. Resolve an ambiguous write by inspecting the committed chain for that command ID before reporting success or re-submitting. A revision conflict never automatically rebases the operator's decision.
- Reject malformed commands, unknown resources, authorization or evidence failures, incompatible or disallowed capabilities, invalid transitions, conflicts and unavailable dependencies as distinguishable outcomes. Report a safe reason and, on conflict, the current revision where the actor can read it. Do not leak storage errors or internal policy material to unprivileged callers.
- The authenticated actor and approver come from verifiable provider/workflow evidence, not fields the caller supplies as identity. Persist human principal, execution identity, decision reason, source/evidence references and approval alongside the revision. Use short-lived workload credentials. Separate publisher, protected writer, approval/incident permissions, freshness signer and read-only host roles. Production has its own AWS account, bucket, encryption key and roles. No signer rotation or rollout approval grants a host wider network, secret, host function or resource privileges.
- CI attests author tests and packaging of the exact artifact. A staging receipt or mandatory host-conformance attestation is not required. Promotion verifies identity, policy and bytes; it never rebuilds. First activation has no serving rollback target; require the host's explicit unavailable behavior before activation.

## Rollout transition rules

| Current state | Authorized action | Result |
| --- | --- | --- |
| No active digest | Activate approved first release | Full exposure on each ready host, not a traffic ramp. Unready or quarantined first release invokes the configured unavailable behavior. |
| Serving baseline | Activate approved upgrade | Keep baseline and load candidate at 0%. The plan binds audience, seed, candidate, baseline and increasing rungs. |
| Warming or ramping | Advance | Exactly the next approved rung, manually, recording the evidence window and reason. Display observed adoption and exposure without automating a health verdict. |
| Warming or ramping | Pause | Keep the current authorized selection, disable advance. Resume is an explicit protected operator action within the same approved plan; outside-plan changes need new approval. |
| Last approved rung | Finish | Keep the approved scope. At 100%, only matching subjects receive the candidate; `set-default` requires approval covering global scope. |
| Active rollout or scoped default | Roll back | Stop selecting the candidate for new work and select only the named, still-authorized baseline, otherwise use unavailable behavior. Do not rewrite receipts. |
| Any | Quarantine | Deny new invocations of the digest in that environment regardless of lane or pin. No cross-environment fan-out. |
| Quarantined digest | Restore with fresh approval | Remove the specific deny; no implicit route or broader authority. |

## Operational surfaces

Emit OTel diagnostics and decision events for CLI/workflow operations and present desired and observed state side by side. Reference dashboards and alert rules distinguish plugin regressions (verified plugin owner), host correctness (host owner), and convergence/freshness/registry outages (registry operations). Route by verified metadata, group related failures, and link the relevant runbook and evidence window. No subject keys or raw predicate inputs in exported telemetry. Use the [data-plane telemetry contract](data-plane.md#observability) for exposure and host health. Measure, but do not promise, global numerical SLOs.
