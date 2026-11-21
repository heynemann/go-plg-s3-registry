# Rewards: roll out a Lua rule and keep retries pinned

From a fresh checkout, run:

```sh
./examples/rewards/run-demo.sh
```

You need Go 1.27.3, Git, Bash, a running local Docker Engine (or Docker Desktop), curl 7.75.0+ with `--aws-sigv4`, jq, and OpenSSL. An uncached run downloads Go dependencies and a digest-pinned Floci image. You don't need an AWS account, AWS credentials, the AWS CLI, or the `sqlite3` command.

The script builds `plg-registry` and the rewards app, packs two real Lua archives, generates independent demo signing keys, and gives Floci and rewards separate loopback ports. The **rewards** HTTP API uses only local fixtures. The **registry** has no HTTP API: `plg-registry` writes to local Floci, and the Go SDK reads the environment bucket from inside rewards. The script uses dummy S3 credentials and never contacts live AWS.

## What you'll see

1. **Publish and activate v1.** Publishing to the publication bucket alone doesn't serve anything. After a proposal, independent approval, and activation, `/readyz` still returns `503` until the renewer issues a proof and the host warms v1. The short proof expires, `/readyz` returns `503` again, and renewing the same decision restores readiness.
2. **Warm v2 at 0%, then advance to 25% of the EU audience.** v1 rejects the synthetic `silver` tier; v2 accepts it. At 0%, a new EU delivery still uses v1. At 25%, `user-2` with `region=EU` selects v2, while the same subject with `region=US` stays on v1. The offline preview reports bucket **2006** for the `prod/eligibility` scope, `user-2`, and the all-zero 64-character seed. That seed is only for the reproducible fixture, not for production plans.
3. **Roll back and restart rewards.** Two EU operations reserved at 25% have persisted v2 receipts. The restarted app opens the same SQLite database. Attempting one old operation still uses v2 and records a 100-cent award exactly once; newly reserved EU work uses v1 and is ineligible.
4. **Quarantine v2.** The second old receipt is now blocked with HTTP `503` problem JSON. The operation stays pending with its original digest; the app neither awards nor substitutes v1.

Each step checks HTTP status and JSON outcomes. The script exits nonzero on a mismatch and removes its own container, process, and temporary files when it exits. The sample also shows the difference between a registry decision being committed and that exact revision being ready in a host.

## Rewards HTTP API

| Endpoint | What it does |
| --- | --- |
| `GET /readyz` | Reports readiness and the effective registry revision in this rewards process. |
| `PUT /v1/deliveries/{id}` | Reserves a delivery with `subject`, `region`, and `tier`. Returns `201` on creation, `200` on identical replay, and `409` if the ID is reused with different input. |
| `POST /v1/deliveries/{id}/attempt` | Uses the stored receipt, not the current rollout, and records `delivered` or `ineligible`. An unavailable or quarantined receipt returns `503` and leaves the work pending. |
| `GET /v1/deliveries/{id}` | Reads the stored delivery status, amount in cents, and exact plugin digest. |

The [OpenAPI contract](api/openapi.yaml) is the source for these endpoints. Reserving commits the receipt before a rule is called. The rule only computes eligibility; completing a delivery and inserting its award are one SQLite transaction. Concurrent attempts can both evaluate the rule, but only one can commit the award. There is no external transfer or production signing material.

## Explore and verify

- [Go contract](contract/contract.go) and [Lua releases](plugins/): the same fixtures are used by the walkthrough and the registry's lifecycle tests. The example packer creates a local proxy for the sample contract; it does not require publishing a Go module.
- [Rewards app](cmd/rewards/): the CLI writes registry state to Floci, the app reads it through `dataplane`, and SQLite belongs to the example app. The app can be run separately with `go run ./examples/rewards/cmd/rewards --help`.
- Run `go test -race -tags integration ./cmd/plg-registry -run '^TestRewardsExample$'` to exercise the same app over HTTP, including concurrent attempts from separate processes against the same database after rollback.

For real deployments, see the [registry operations guide](../../docs/operations.md).
