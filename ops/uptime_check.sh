#!/usr/bin/env bash
# Assertions of the hosted runner's daily uptime check (uptime.yml). Every subcommand reads files
# the workflow already fetched, so the same assertions run against fixtures in the workflow's dry
# run and in uptime_check_test.sh. Annotations go to stdout as GitHub workflow commands.
#
#   uptime_check.sh list LIST --out DOC [--floor-file F] [--min-version N] [--pub KEY] [--now EPOCH]
#   uptime_check.sh release DOC ATTESTATION --spec-out FILE
#   uptime_check.sh router DOC ATTESTATION
#   uptime_check.sh health HEALTH [--pre-r1]
#   uptime_check.sh host HOST HEALTH --route-out FILE
#   uptime_check.sh identity IDENTITY
#   uptime_check.sh approval-key
#
# LIST is the signed approved-releases envelope; DOC is the document `list` verified out of it.
# ATTESTATION is `tinfoil attestation verify -j` output. HEALTH, HOST and IDENTITY are the bodies
# `tinfoil http get` printed for /health, /v2/host and the pairing identity document.
#
# The destination repository's Actions logs are public: /v2/host and the identity document carry host,
# installation, enrollment and family identifiers and are checked for shape, never printed.
set -euo pipefail

readonly RUNNER_REPO="tildeapp/tilde-runner"
readonly ROUTER_REPO="tinfoilsh/confidential-model-router"
# The runner reports a list `stale` past seven days (runner/rust/src/trust_list.rs STALE_AFTER) and
# keeps using it; this check is what turns an unrefreshed list into a page (design §8.2).
readonly MAX_AGE_SECONDS=604800
readonly WARN_AGE_SECONDS=518400
# Tolerated clock skew before an issued_at in the future is refused: a future-dated list would
# otherwise never age past the staleness limit.
readonly FUTURE_SKEW_SECONDS=3600

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
failures=0

error() {
  echo "::error::$*"
  failures=$((failures + 1))
}
warn() { echo "::warning::$*"; }
die() {
  echo "::error::$*"
  exit 1
}
finish() {
  [ "$failures" -eq 0 ] || exit 1
}
usage() { die "usage: uptime_check.sh $1 … (see the header of uptime_check.sh)"; }

# The verifier and the compiled approval key come from the Tilde repository (runner/ops beside
# native/runner-client) or, in tildeapp/tilde-runner, from the copy mirror_uptime.sh wrote under
# ops/approved-releases.
module_dir() {
  if [ -f "$here/../../native/runner-client/go.mod" ]; then
    echo "$here/../../native/runner-client"
  elif [ -f "$here/approved-releases/go.mod" ]; then
    echo "$here/approved-releases"
  else
    die "No approved-releases verifier beside $here"
  fi
}

approval_key() {
  local transport="$here/../../native/runner-client/internal/transport/transport.go"
  local mirrored="$here/approved-releases/approval-public-key"
  if [ -f "$transport" ]; then
    sed -n 's/^[[:space:]]*ApprovalPublicKey[[:space:]]*=[[:space:]]*"\([^"]*\)".*/\1/p' "$transport"
  elif [ -f "$mirrored" ]; then
    tr -d '[:space:]' <"$mirrored"
  fi
}

verifier() {
  if [ -n "${APPROVED_RELEASES_BIN:-}" ]; then
    "$APPROVED_RELEASES_BIN" "$@"
  else
    go -C "$(module_dir)" run ./cmd/approved-releases "$@"
  fi
}

# RFC 3339 to epoch seconds; jq's fromdateiso8601 accepts only whole seconds in UTC.
readonly JQ_EPOCH='
  def rfc3339_epoch:
    capture("^(?<d>[0-9]{4}-[0-9]{2}-[0-9]{2})[Tt](?<t>[0-9]{2}:[0-9]{2}:[0-9]{2})(\\.[0-9]+)?(?<z>[Zz]|(?<s>[+-])(?<h>[0-9]{2}):(?<m>[0-9]{2}))$")
    | ((.d + "T" + .t + "Z") | fromdateiso8601)
      - (if .s == null then 0
         else (if .s == "+" then 1 else -1 end) * ((.h | tonumber) * 3600 + (.m | tonumber) * 60)
         end);'

days() { echo "$(($1 / 86400))d $((($1 % 86400) / 3600))h"; }

cmd_list() {
  local list="" out="" floor_file="" min_version="" pub="" now=""
  list="${1:-}"
  shift || true
  while [ $# -gt 0 ]; do
    case "$1" in
      --out) out="${2:-}" ;;
      --floor-file) floor_file="${2:-}" ;;
      --min-version) min_version="${2:-}" ;;
      --pub) pub="${2:-}" ;;
      --now) now="${2:-}" ;;
      *) usage list ;;
    esac
    shift
    shift || true
  done
  [ -n "$list" ] && [ -n "$out" ] || usage list
  [ -s "$list" ] || die "The approved-releases list is missing or empty"
  # `go -C` runs the verifier from its module directory.
  list="$(cd "$(dirname "$list")" && pwd)/$(basename "$list")"
  [ -n "$pub" ] || pub="$(approval_key)"
  [ -n "$pub" ] || die "ApprovalPublicKey is not set in native/runner-client/internal/transport/transport.go; no list can verify"
  [ -n "$now" ] || now="$(date -u +%s)"

  local detail
  if ! verifier verify -pub "$pub" -in "$list" >"$out" 2>"$out.err"; then
    detail="$(head -n 1 "$out.err")"
    rm -f "$out" "$out.err"
    die "The approved-releases list does not verify under the compiled approval key: ${detail:-no detail}"
  fi
  rm -f "$out.err"

  local version issued_at issued
  version="$(jq -r '.version' "$out")"
  issued_at="$(jq -r '.issued_at' "$out")"
  issued="$(jq -r "$JQ_EPOCH"' .issued_at | rfc3339_epoch' "$out" 2>/dev/null)" \
    || die "The approved-releases list's issued_at ($issued_at) is not RFC 3339"
  echo "Approved-releases list: version $version, issued_at $issued_at, $(jq -r '"\(.approved | length) approved, \(.revoked | length) revoked, router \(.router.approved | length) approved, \(.router.revoked | length) revoked"' "$out")"

  [ "$(jq -r '.router.repo' "$out")" = "$ROUTER_REPO" ] \
    || error "The approved-releases list names router repo $(jq -r '.router.repo' "$out"), expected $ROUTER_REPO"

  local floor=0 seen=""
  [[ "${min_version:-0}" =~ ^[0-9]+$ ]] || die "APPROVED_LIST_MIN_VERSION must be a whole number"
  floor="${min_version:-0}"
  if [ -n "$floor_file" ] && [ -s "$floor_file" ]; then
    seen="$(tr -d '[:space:]' <"$floor_file")"
    [[ "$seen" =~ ^[0-9]+$ ]] || die "The cached list version is not a whole number"
    if [ "$seen" -gt "$floor" ]; then floor="$seen"; fi
  fi
  if [ "$version" -lt "$floor" ]; then
    error "The approved-releases list went backwards: version $version is below $floor (last seen ${seen:-none}, APPROVED_LIST_MIN_VERSION ${min_version:-unset}). A served older list can restore revoked releases."
  fi

  local age=$((now - issued))
  if [ "$age" -lt "-$FUTURE_SKEW_SECONDS" ]; then
    error "The approved-releases list's issued_at ($issued_at) is in the future"
  elif [ "$age" -ge "$MAX_AGE_SECONDS" ]; then
    error "The approved-releases list is $(days "$age") old (issued_at $issued_at); re-sign and publish a new version (fails past 7 days)"
  elif [ "$age" -ge "$WARN_AGE_SECONDS" ]; then
    warn "The approved-releases list is $(days "$age") old; this check fails at 7 days"
  fi

  finish
  if [ -n "$floor_file" ]; then
    mkdir -p "$(dirname "$floor_file")"
    echo "$version" >"$floor_file"
  fi
  echo "The approved-releases list verifies, is current and did not go backwards."
}

# Prints the record's safe fields and leaves the attested digest in $attested.
attested_digest() {
  local record="$1" what="$2" repo="$3" status
  if ! jq -e 'type == "object"' "$record" >/dev/null 2>&1; then
    die "$what attestation produced no record"
  fi
  jq -c '{enclave, repo, digest, status, freshness_expires_at}' "$record"
  status="$(jq -r '.status // "none"' "$record")"
  [ "$status" = "ok" ] || die "$what attestation status is $status"
  [ "$(jq -r '.repo // ""' "$record")" = "$repo" ] || die "$what attestation is for $(jq -r '.repo // "no repo"' "$record"), expected $repo"
  attested="$(jq -r '.digest // ""' "$record")"
  [[ "$attested" =~ ^[0-9a-f]{64}$ ]] || die "$what attestation has no release digest"
}

cmd_release() {
  local doc="${1:-}" record="${2:-}" spec_out=""
  [ "${3:-}" = "--spec-out" ] && spec_out="${4:-}"
  [ -n "$doc" ] && [ -n "$record" ] && [ -n "$spec_out" ] || usage release
  attested_digest "$record" "Runner" "$RUNNER_REPO"
  if jq -e --arg d "$attested" '.revoked | index($d)' "$doc" >/dev/null; then
    die "The live runner release sha256:$attested is revoked by the signed approved-releases list"
  fi
  local tag
  tag="$(jq -r --arg d "$attested" 'first(.approved[] | select(.digest == $d) | .tag) // ""' "$doc")"
  [ -n "$tag" ] || die "The live runner release sha256:$attested is not in the signed list's approved releases"
  echo "Live runner release $tag (sha256:$attested) is approved."
  echo "$RUNNER_REPO@$tag@sha256:$attested" >"$spec_out"
}

# The runner's router rule (runner/rust/src/trust_list.rs): the attestation proves the release is
# Tinfoil's Sigstore-attested build of ROUTER_REPO, and the signed list must name ROUTER_REPO and
# not revoke its digest. `router.approved` is reported, never required.
cmd_router() {
  local doc="${1:-}" record="${2:-}"
  [ -n "$doc" ] && [ -n "$record" ] || usage router
  attested_digest "$record" "Router" "$ROUTER_REPO"
  [ "$(jq -r '.router.repo' "$doc")" = "$ROUTER_REPO" ] \
    || die "The signed approved-releases list names router repo $(jq -r '.router.repo' "$doc"), not $ROUTER_REPO. Hosted inference fails closed."
  if jq -e --arg d "$attested" '.router.revoked | index($d)' "$doc" >/dev/null; then
    die "Router release sha256:$attested is revoked by the signed approved-releases list. Hosted inference fails closed."
  fi
  if jq -e --arg d "$attested" '.router.approved | index($d)' "$doc" >/dev/null; then
    echo "Router release sha256:$attested is not revoked (and is listed in router.approved)."
  else
    echo "Router release sha256:$attested is not revoked (not listed in router.approved, which runners before the provenance rule require)."
  fi
}

cmd_health() {
  local health="${1:-}" pre_r1=false
  [ "${2:-}" = "--pre-r1" ] && pre_r1=true
  [ -n "$health" ] || usage health
  jq -e 'type == "object"' "$health" >/dev/null 2>&1 || die "/health did not return a JSON object"
  jq -c '{service, state, enrolled, version, store, volume_error, trust_list, host, families, refused_codes, isolation}
         | with_entries(select(.value != null))' "$health"

  jq -e '.service == "tilde-runner" and .state == "ready" and .enrolled == true' "$health" >/dev/null \
    || error "Runner is attested but not ready and enrolled (state: $(jq -r '.state' "$health"))"
  jq -e '.store == "volume" and (has("volume_error") | not)' "$health" >/dev/null \
    || error "Runner state is not on the encrypted volume (store: $(jq -r '.store' "$health"), volume_error: $(jq -r '.volume_error // "none"' "$health"))"

  if ! jq -e 'has("trust_list")' "$health" >/dev/null; then
    if $pre_r1; then
      warn "/health has no trust_list (a runner before R1); tolerated by --pre-r1"
    else
      error "/health has no trust_list: the runner predates R1 and checks no signed list"
    fi
  else
    local status age
    status="$(jq -r '.trust_list.status // "none"' "$health")"
    age="$(jq -r '.trust_list.age_seconds // ""' "$health")"
    case "$status" in
      missing)
        error "The runner has no verified approved-releases list (trust_list.status missing); hosted inference fails with release_not_approved"
        ;;
      current | stale)
        if ! [[ "$age" =~ ^[0-9]+$ ]]; then
          error "trust_list.age_seconds is missing or not a whole number"
        elif [ "$age" -ge "$MAX_AGE_SECONDS" ]; then
          error "The runner's approved-releases list is $(days "$age") old (trust_list.status $status); publish a new version (fails past 7 days)"
        elif [ "$status" = "stale" ]; then
          warn "The runner reports its approved-releases list stale at $(days "$age")"
        elif [ "$age" -ge "$WARN_AGE_SECONDS" ]; then
          warn "The runner's approved-releases list is $(days "$age") old; this check fails at 7 days"
        fi
        ;;
      *) error "Unknown trust_list.status: $status" ;;
    esac
  fi

  # `families` and `host` arrive with R2 (tilde-runner hosted); R1 serves neither.
  if jq -e 'has("families")' "$health" >/dev/null; then
    if ! jq -e '.families | type == "object"
          and ([.stopped, .loading, .ready, .unreadable, .refused, .breaker_open]
               | all(type == "number" and . >= 0 and . == floor))' "$health" >/dev/null; then
      error "/health families is malformed"
    else
      local count
      count="$(jq -r '.families.unreadable' "$health")"
      [ "$count" -eq 0 ] || error "$count families' state is unreadable (families.unreadable)"
      count="$(jq -r '.families.refused' "$health")"
      [ "$count" -eq 0 ] || error "$count families refused (refused_codes: $(jq -c '.refused_codes // {}' "$health"))"
      count="$(jq -r '.families.breaker_open' "$health")"
      [ "$count" -eq 0 ] || error "$count families have an open breaker (families.breaker_open)"
    fi
    jq -e '.host == "registered"' "$health" >/dev/null \
      || error "The host is not registered (host: $(jq -r '.host // "absent"' "$health")); no host session opened"
  fi

  finish
  echo "Runner health passes."
}

cmd_host() {
  local host="${1:-}" health="${2:-}" route_out=""
  [ "${3:-}" = "--route-out" ] && route_out="${4:-}"
  [ -n "$host" ] && [ -n "$health" ] && [ -n "$route_out" ] || usage host
  # The Tinfoil shim answers an unrouted path 404 with this OpenAI-style body; `tinfoil http get`
  # prints the body only, not the status.
  if jq -e '.error.code == "not_found"' "$host" >/dev/null 2>&1; then
    if jq -e 'has("families")' "$health" >/dev/null 2>&1; then
      die "/health is R2's but /v2/host answered not_found"
    fi
    echo "/v2/host is not served (R1)."
    echo absent >"$route_out"
    return
  fi
  jq -e 'type == "object"
         and (keys == ["host_id", "routing_public_key", "signing_public_key"])
         and (.host_id | type == "string"
              and test("^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"))
         and ([.signing_public_key, .routing_public_key]
              | all(type == "string" and test("^[0-9a-f]{64}$")))' "$host" >/dev/null 2>&1 \
    || die "/v2/host does not have exactly host_id, signing_public_key and routing_public_key in lowercase"
  echo "/v2/host has the expected shape."
  echo present >"$route_out"
}

cmd_identity() {
  local identity="${1:-}"
  [ -n "$identity" ] || usage identity
  jq -e '
    (.generation | type == "number")
    and ([.signing_public_key, .encryption_public_key] | all(type == "string" and test("^[0-9a-f]{64}$")))
    and ([.installation_id, .enrollment_id, .family_id] | all(type == "string" and length > 0))
  ' "$identity" >/dev/null 2>&1 || die "Runner identity is missing required fields"
  echo "Runner identity has the expected shape."
}

command="${1:-}"
shift || true
case "$command" in
  list) cmd_list "$@" ;;
  release) cmd_release "$@" ;;
  router) cmd_router "$@" ;;
  health) cmd_health "$@" ;;
  host) cmd_host "$@" ;;
  identity) cmd_identity "$@" ;;
  approval-key)
    key="$(approval_key)"
    [ -n "$key" ] || die "ApprovalPublicKey is not set"
    echo "$key"
    ;;
  *) die "usage: uptime_check.sh list|release|router|health|host|identity|approval-key …" ;;
esac
