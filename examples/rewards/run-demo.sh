#!/usr/bin/env bash
set -euo pipefail
umask 077

say() { printf '\n==> %s\n' "$*"; }
die() { printf 'rewards demo: %s\n' "$*" >&2; exit 1; }

for tool in go git docker curl jq openssl; do
  command -v "$tool" >/dev/null || die "missing dependency: $tool (see examples/rewards/README.md)"
done
registry_bin=''
if [[ -n "${PLG_REGISTRY_BIN:-}" ]]; then
  registry_bin=$(type -P -- "$PLG_REGISTRY_BIN") || die "not an executable: $PLG_REGISTRY_BIN"
  case "$registry_bin" in /*) ;; *) registry_bin="$PWD/$registry_bin" ;; esac
fi
cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.."
work=$(mktemp -d "${TMPDIR:-/tmp}/registry-rewards.XXXXXXXX")
work=$(cd -- "$work" && pwd -P)
rewards_pid=''
stop_rewards() {
  if [[ -n "$rewards_pid" ]]; then
    kill "$rewards_pid" 2>/dev/null || true
    wait "$rewards_pid" || true
    rewards_pid=''
  fi
}
cleanup() {
  local status=$? cid
  trap - EXIT
  stop_rewards
  if (( status != 0 )) && [[ -s "$work/rewards.log" ]]; then
    cat "$work/rewards.log" >&2
  fi
  if [[ -s "$work/floci.cid" ]]; then
    cid=$(<"$work/floci.cid")
    docker rm -f "$cid" >/dev/null 2>&1 || true
  fi
  rm -rf -- "$work"
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

image='floci/floci@sha256:a0fbf944d7f338cc0856f1ef83831ea749ff2be71956eb7a7fce08fc21458e19'
publication='rewards-publication'
destination='rewards-environment'
epoch='initial'
region='us-east-1'
config="$work/deployment.json"
response="$work/response.json"
evidence='https://example.com/rewards/demo-evidence'
export NO_PROXY="127.0.0.1${NO_PROXY:+,$NO_PROXY}"

local_curl() { curl --disable --noproxy '*' --silent --show-error "$@"; }

say 'Prepare the CLI and rewards HTTP app, and pack both Lua releases'
if [[ -z "$registry_bin" ]]; then
  registry_bin="$work/plg-registry"
  go build -o "$registry_bin" ./cmd/plg-registry
fi
go build -o "$work/rewards" ./examples/rewards/cmd/rewards
go run ./examples/rewards/cmd/pack --out "$work" >"$work/pack.json"

say 'Start pinned Floci on a Docker-assigned loopback port'
docker run --rm --detach --cidfile "$work/floci.cid" --publish 127.0.0.1::4566 \
  --env FLOCI_STORAGE_MODE=memory "$image" >/dev/null
binding=$(docker port "$(<"$work/floci.cid")" 4566/tcp)
[[ "$binding" =~ ^127\.0\.0\.1:[0-9]+$ ]] || die "unexpected Floci port binding: $binding"
endpoint="http://$binding"
deadline=$((SECONDS + 60))
until local_curl --fail --max-time 2 "$endpoint/_floci/health" >/dev/null 2>&1; do
  (( SECONDS < deadline )) || die "Floci did not become healthy at $endpoint"
  sleep 0.2
done
for bucket in "$publication" "$destination"; do
  # CreateBucket in us-east-1 has an empty body (the SHA-256 below).
  local_curl --fail --max-time 10 --request PUT --aws-sigv4 "aws:amz:$region:s3" --user 'test:test' \
    --header 'x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855' \
    "$endpoint/$bucket" >/dev/null
done

say 'Generate independent demo signing keys and the deployment trust file'
for role in author proposer approver decider responder renewer recoverer publisher-admin; do
  openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:prime256v1 -out "$work/$role.pem"
  if [[ "$role" != author ]]; then
    pkix=$(openssl pkey -in "$work/$role.pem" -pubout -outform DER | openssl base64 -A)
    jq -cn --arg role "$role" --arg pkix "$pkix" \
      '{role:$role,key_id:("local:"+$role),public_key_pkix:$pkix}' >>"$work/authorities.jsonl"
  fi
done
openssl pkey -in "$work/author.pem" -pubout -out "$work/author-public.pem"
jq -n --arg epoch "$epoch" --arg region "$region" --arg dest "$destination" --arg pub "$publication" \
  --slurpfile authorities "$work/authorities.jsonl" '{
    schema_version:1, scope:{registry:"demo",environment:"prod",plugin:"eligibility",epoch:$epoch},
    destination:{bucket:$dest,region:$region}, publication:{bucket:$pub,region:$region},
    max_lease:"10m", authorities:$authorities
  }' >"$config"

registry() { "$registry_bin" --endpoint "$endpoint" --output json "$@"; }
publish_cli() { registry --registry demo --bucket "$publication" --region "$region" "$@"; }
control() {
  local role=$1
  shift
  registry --config "$config" --local-key "$work/$role.pem" "$@"
}
publish() {
  local version=$1 name=$2 commit
  commit=$(jq -er --arg key "${name}_commit" '.[$key] | select(test("^[a-f0-9]{40}$"))' "$work/pack.json")
  publish_cli release publish --plugin eligibility --version "$version" --artifact "$work/$name.plg" \
    --source-commit "$commit" --key-id local:author --local-key "$work/author.pem" |
    jq -er --arg version "$version" 'select(.version == $version) | .artifact_digest | select(test("^sha256:[a-f0-9]{64}$"))'
}
approve() {
  plan_id=$(control proposer rollout propose --plan "$1" | jq -er '.plan_id | select(test("^sha256:[a-f0-9]{64}$"))')
  approval_id=$(control approver rollout approve --plan-id "$plan_id" | jq -er '.approval_id | select(test("^sha256:[a-f0-9]{64}$"))')
}
command_file="$work/command.json"
apply() {
  local role=$1 group=$2 action=$3 expected_generation=$4 phase=$5 rung=$6
  control "$role" "$group" "$action" --command "$command_file" >"$work/applied.json"
  decision=$(jq -er --argjson generation "$expected_generation" --arg phase "$phase" --argjson rung "$rung" '
    select(.status == "applied" and .decision.generation == $generation
      and .decision.state.phase == $phase and .decision.state.rung == $rung)
    | .decision.decision_id | select(test("^sha256:[a-f0-9]{64}$"))
  ' "$work/applied.json")
  generation=$expected_generation
}
activate() {
  local id=$1 expected=$2 next=$3 phase=$4
  jq -n --arg id "$id" --arg expected "$expected" --arg plan "$plan_id" --arg approval "$approval_id" \
    '{id:$id,expected:$expected,plan_id:$plan,approval_id:$approval,reason:"activate approved demo plan"}' >"$command_file"
  apply decider rollout activate "$next" "$phase" 0
}
renew() {
  control renewer freshness renew --duration "$1" |
    jq -er --arg decision "$decision" '
      select(.status == "renewed" and .freshness == "current" and .decision.decision_id == $decision)
      | .expires_at | strings
    '
}

start_rewards() {
  local end=$((SECONDS + 45)) line
  : >"$work/rewards.log"
  "$work/rewards" --config "$config" --endpoint "$endpoint" --db "$work/rewards.sqlite" \
    --listen 127.0.0.1:0 >>"$work/rewards.log" 2>&1 &
  rewards_pid=$!
  while (( SECONDS < end )); do
    while IFS= read -r line; do
      if [[ "$line" =~ ^listening\ (http://127\.0\.0\.1:[0-9]+)$ ]]; then
        rewards_url=${BASH_REMATCH[1]}
        return
      fi
    done <"$work/rewards.log"
    kill -0 "$rewards_pid" 2>/dev/null || die 'rewards exited during startup'
    sleep 0.2
  done
  die 'rewards did not announce its loopback listener'
}
request() {
  local method=$1 path=$2
  shift 2
  local_curl --max-time 10 --request "$method" --output "$response" --write-out '%{http_code} %{content_type}' \
    "$@" "$rewards_url$path"
}
expect_http() {
  local expected=$1 method=$2 path=$3 result
  shift 3
  result=$(request "$method" "$path" "$@")
  if [[ "${result%% *}" != "$expected" ]]; then
    cat "$response" >&2
    die "$method $path returned ${result%% *}, expected $expected"
  fi
  content_type=${result#* }
}
wait_ready() {
  local expected=$1 expected_ready=false expected_decision=${2:-} end=$((SECONDS + 30)) result
  [[ "$expected" != 200 ]] || expected_ready=true
  while (( SECONDS < end )); do
    if result=$(request GET /readyz --max-time 2 2>/dev/null) && [[ "${result%% *}" == "$expected" ]] &&
      jq -e --argjson ready "$expected_ready" --arg decision "$expected_decision" \
        --argjson generation "${generation:-0}" --arg epoch "$epoch" '
          .ready == $ready and ($decision == "" or
            (.effective.decision == $decision and .effective.generation == $generation and .effective.epoch == $epoch))
        ' "$response" >/dev/null; then
      return
    fi
    kill -0 "$rewards_pid" 2>/dev/null || die 'rewards exited while waiting for readiness'
    sleep 0.2
  done
  [[ ! -s "$response" ]] || cat "$response" >&2
  die "expected /readyz HTTP $expected for ${expected_decision:-any decision}"
}
put_delivery() {
  local code=$1 id=$2 region=$3
  expect_http "$code" PUT "/v1/deliveries/$id" --header 'Content-Type: application/json' \
    --data "{\"subject\":\"user-2\",\"region\":\"$region\",\"tier\":\"silver\"}"
}
assert_delivery() {
  local id=$1 status=$2 amount=$3 digest=$4
  jq -e --arg id "$id" --arg status "$status" --argjson amount "$amount" --arg digest "$digest" '
    .id == $id and .status == $status and .amount_cents == $amount and .plugin_digest == $digest
  ' "$response" >/dev/null || { cat "$response" >&2; die "expected $id: $status ($amount cents), $digest"; }
  jq -c '{id,status,amount_cents,plugin_digest}' "$response"
}
reserve() {
  put_delivery 201 "$1" "$2"
  assert_delivery "$1" pending 0 "$3"
}
attempt() {
  expect_http 200 POST "/v1/deliveries/$1/attempt"
  assert_delivery "$@"
}

say 'Publish v1 and v2; publication alone does not make a host ready'
printf -v workflow_revision '%040d' 0
publish_cli plugin onboard --plugin eligibility --owner rewards --on-call rewards-ops \
  --runbook https://example.com/rewards/runbook --repository example/rewards-author \
  --workflow "heynemann/go-plg-s3-registry/.github/workflows/publish-plugin.yml@$workflow_revision" \
  --key-id local:author --public-key "$work/author-public.pem" >/dev/null
first=$(publish v1.0.0 first)
second=$(publish v2.0.0 second)
[[ "$first" != "$second" ]] || die 'expected distinct archive digests'
printf 'v1: %s\nv2: %s\n' "$first" "$second"
start_rewards
wait_ready 503

say 'Activate v1; a signed activation still needs freshness to serve'
jq --arg digest "$first" '{scope,candidate:{version:"v1.0.0",digest:$digest},unavailable:"hold"}' "$config" >"$work/first-plan.json"
approve "$work/first-plan.json"
activate initial '' 1 serving
registry --config "$config" status | jq -e --arg decision "$decision" \
  '.decision.decision_id == $decision and .freshness == "unavailable"' >/dev/null
wait_ready 503
short_expiry=$(renew 10s)
printf 'Short lease expires at %s\n' "$short_expiry"
wait_ready 200 "$decision"
wait_ready 503 "$decision"
long_expiry=$(renew 10m)
printf 'Expired: /readyz returned 503. Renewed until %s\n' "$long_expiry"
wait_ready 200 "$decision"

say 'Warm v2 at 0%; EU silver still uses v1'
# A fixed seed is for this reproducible preview only.
printf -v seed '%064d' 0
jq --arg first "$first" --arg second "$second" --arg seed "$seed" --arg evidence "$evidence" '{
  scope, candidate:{version:"v2.0.0",digest:$second}, baseline:{version:"v1.0.0",digest:$first},
  target:{version:1,expression:"region == \"EU\"",attributes:{region:"string"},seed:$seed},
  rungs:[2500,10000], evidence:[$evidence], stop_conditions:["incorrect reward outcome"], unavailable:"hold"
}' "$config" >"$work/upgrade-plan.json"
approve "$work/upgrade-plan.json"
activate warm "$decision" 2 warming
renew 10m >/dev/null
wait_ready 200 "$decision"
reserve warm-eu EU "$first"
attempt warm-eu ineligible 0 "$first"

say 'Advance to 25% of matching EU subjects; US silver stays on v1'
printf '%s\n' '{"region":"EU"}' >"$work/eu.json"
"$registry_bin" --output json rollout preview --plan "$work/upgrade-plan.json" \
  --subject user-2 --attrs "$work/eu.json" --rung 2500 | jq -e 'select(.match == true and .bucket == 2006 and .candidate == true)'
jq -n --arg expected "$decision" --arg approval "$approval_id" --arg evidence "$evidence" \
  '{id:"rung-25",expected:$expected,approval_id:$approval,reason:"observed warm host",rung:2500,evidence:[$evidence]}' >"$command_file"
apply decider rollout advance 3 ramping 2500
renew 10m >/dev/null
wait_ready 200 "$decision"
reserve ramp-us US "$first"
attempt ramp-us ineligible 0 "$first"
reserve eu-pinned EU "$second"
put_delivery 200 eu-pinned EU
assert_delivery eu-pinned pending 0 "$second"
put_delivery 409 eu-pinned US
reserve eu-blocked EU "$second"

say 'Roll back and restart rewards on the same SQLite file'
jq -n --arg expected "$decision" '{id:"rollback",expected:$expected,incident:"demo-1",reason:"return to v1"}' >"$command_file"
apply responder rollout rollback 4 rolled-back 0
renew 10m >/dev/null
stop_rewards
start_rewards
wait_ready 200 "$decision"
expect_http 200 GET /v1/deliveries/eu-pinned
assert_delivery eu-pinned pending 0 "$second"
attempt eu-pinned delivered 100 "$second"
attempt eu-pinned delivered 100 "$second"
reserve after-rollback EU "$first"
attempt after-rollback ineligible 0 "$first"

say 'Quarantine v2; the other pinned delivery stays pending, not repinned'
jq -n --arg expected "$decision" --arg digest "$second" \
  '{id:"quarantine",expected:$expected,digest:$digest,incident:"demo-2",reason:"deny v2 invocations"}' >"$command_file"
apply responder release quarantine 5 rolled-back 0
renew 10m >/dev/null
wait_ready 200 "$decision"
expect_http 503 POST /v1/deliveries/eu-blocked/attempt
[[ "${content_type%%;*}" == application/problem+json ]] || die "expected problem JSON, got $content_type"
jq -e 'select(.status == 503 and .type == "urn:rewards:quarantined")' "$response"
expect_http 200 GET /v1/deliveries/eu-blocked
assert_delivery eu-blocked pending 0 "$second"

say 'Demo passed; removing its temporary container, process, keys and SQLite database'
