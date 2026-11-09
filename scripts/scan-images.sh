#!/usr/bin/env bash
# Cobe News – scan the three images with Trivy, with the same gate as the release pipeline (docs/SICHERHEIT-SCANS.md;
# docs/BETRIEB.md: Release): a high or critical finding that has a fixed version fails, findings without a fix are
# reported but do not fail. The scanned images are only read – never pulled into Docker, never tagged; no compose, no
# container of the app touched. Without a local trivy it pulls Trivy's own image (pinned below) and keeps its database
# in a Docker volume.
#
#   scripts/scan-images.sh                  the local build: cobe-news:latest, cobe-news-db:latest, cobe-news-proxy:latest
#   scripts/scan-images.sh 0.1.55           the released images of a version, read from ghcr.io
#   scripts/scan-images.sh REF [REF …]      any image references (name:tag, name@sha256:… – e.g. the digest cosign verified)
#
# Environment:
#   OUT        report folder (default trivy-reports/<UTC time>): per image and platform trivy-<reference>.json (full
#              report, all severities, also without a fix), trivy-<reference>.txt (the same as a table), and summary.md
#   PLATFORMS  e.g. "linux/amd64 linux/arm64" – each platform of a multi-arch image (default: the one for this machine)
#   TRIVY      a Trivy binary (default: `trivy` on the PATH), or `docker`: Trivy's official image, pinned below – also
#              without a local binary; its vulnerability database stays in the volume TRIVY_CACHE_VOLUME
#              (default cobe-news-trivy-cache)
#
# Exit code 0: no fixable high or critical finding; 1: at least one (listed); 2: wrong use or a scan failed.
set -euo pipefail

# the gate is this script's alone: no trivy.yaml or .trivyignore (--config "" --ignorefile "" below) and no TRIVY_*
# setting from the environment – except where the images come from, the database mirror and the cache
for v in $(env | sed -n 's/^\(TRIVY_[A-Za-z0-9_]*\)=.*/\1/p'); do
  case "$v" in
    TRIVY_IMAGE_SRC | TRIVY_DB_REPOSITORY | TRIVY_CACHE_DIR | TRIVY_CACHE_VOLUME) ;;
    *) unset "$v" ;;
  esac
done

# the same version as the release pipeline (.github/workflows/release.yml, TRIVY_VERSION) – the image by its digest
TRIVY_IMAGE="aquasec/trivy:0.76.2@sha256:8f6bb947dbc528902e11f2f5be52f7b519f6a39d5d148f41166f2040499768fb"
REGISTRY="ghcr.io/g0urmetd"
NOCONFIG=(--config "" --ignorefile "")

usage() {
  sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//' >&2
  exit 2
}

src=()
case "${1:-}" in
  -h | --help) usage ;;
  "")
    refs=(cobe-news:latest cobe-news-db:latest cobe-news-proxy:latest)
    src=(--image-src docker) # the local build only – never a download under the same name
    ;;
  *)
    if [ "$#" -eq 1 ] && [[ "$1" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
      refs=("$REGISTRY/cobe-news:$1" "$REGISTRY/cobe-news-db:$1" "$REGISTRY/cobe-news-proxy:$1")
      src=(--image-src remote) # from the registry, not a local image of the same name
    else
      for r in "$@"; do
        [[ "$r" =~ ^[A-Za-z0-9][A-Za-z0-9._/:@-]*$ ]] || { echo "not an image reference: $r" >&2; exit 2; }
      done
      refs=("$@")
    fi
    ;;
esac

OUT="${OUT:-trivy-reports/$(date -u +%Y%m%d-%H%M%S)}"
mkdir -p "$OUT"
OUT="$(cd "$OUT" && pwd)"
read -r -a platforms <<<"${PLATFORMS:-}"
[ "${#platforms[@]}" -gt 0 ] || platforms=("")

# Trivy: the local binary, or the pinned image (reports are written here from its standard output – the container only
# reads the folder; the Docker socket only to read local images)
TRIVY="${TRIVY:-$(command -v trivy || echo docker)}"
[ "$TRIVY" != docker ] || TRIVY=""
trivy_run() {
  if [ -n "$TRIVY" ]; then
    "$TRIVY" "$@"
  else
    local sock=() pass=()
    [ "${src[*]:-}" = "--image-src remote" ] || sock=(-v /var/run/docker.sock:/var/run/docker.sock)
    [ -z "${TRIVY_IMAGE_SRC:-}" ] || pass+=(-e "TRIVY_IMAGE_SRC=$TRIVY_IMAGE_SRC")
    [ -z "${TRIVY_DB_REPOSITORY:-}" ] || pass+=(-e "TRIVY_DB_REPOSITORY=$TRIVY_DB_REPOSITORY")
    docker run --rm -i \
      -v "${TRIVY_CACHE_VOLUME:-cobe-news-trivy-cache}:/root/.cache/trivy" -v "$OUT:/out:ro" ${sock[@]+"${sock[@]}"} \
      ${pass[@]+"${pass[@]}"} "$TRIVY_IMAGE" "$@"
  fi
}
report() { # the path of a report file as Trivy sees it
  if [ -n "$TRIVY" ]; then echo "$OUT/$1"; else echo "/out/$1"; fi
}
# the first value of "key" inside "ImageConfig" of a JSON report (Trivy writes it indented, one key per line)
image_config() {
  awk -v k="\"$2\":" '/"ImageConfig": \{/ { on = 1 } on && $1 == k { gsub(/[",]/, "", $2); print $2; exit }' "$1"
}

# one line per finding: severity, fixed/unfixed, package (with its file outside the OS packages), installed, fixed version, ID
FINDINGS='{{- range $r := . }}{{- range .Vulnerabilities }}{{ .Severity }}{{ "\t" }}{{ if .FixedVersion }}fixed{{ else }}unfixed{{ end }}{{ "\t" }}{{ .PkgName }}{{ if ne $r.Class "os-pkgs" }} ({{ $r.Target }}){{ end }}{{ "\t" }}{{ .InstalledVersion }}{{ "\t" }}{{ .FixedVersion }}{{ "\t" }}{{ .VulnerabilityID }}{{ "\n" }}{{- end }}{{- end }}'

status=0
rows=""
blocked=""
used=" "
failed() { # label, reason: a step other than the gate failed – exit 2, the summary's row says why
  echo "$2: $1" >&2
  rows="$rows| \`$1\` | – | – | – | – | – | $2 |"$'\n'
  status=2
}
for ref in "${refs[@]}"; do
  # the report's name: the whole reference (registry, path, tag; a digest shortened to 12), safe as a file name
  name="$ref"
  if [[ "$name" =~ ^(.*)@sha256:([0-9a-f]{12})[0-9a-f]*$ ]]; then
    name="${BASH_REMATCH[1]}@${BASH_REMATCH[2]}"
  fi
  name="$(printf '%s' "$name" | tr -c 'A-Za-z0-9._-' '_')"
  for platform in "${platforms[@]}"; do
    plat=()
    base="trivy-$name"
    if [ -n "$platform" ]; then
      plat=(--platform "$platform")
      base="$base-$(printf '%s' "${platform#*/}" | tr -c 'A-Za-z0-9._-' '_')"
    fi
    stem="$base"
    n=2
    while [[ "$used" == *" $base "* ]]; do
      base="$stem-$n"
      n=$((n + 1))
    done
    used="$used$base "
    label="$ref${platform:+ ($platform)}"
    echo "== $label"
    # the full report: every severity, also without a fix
    if ! trivy_run image --quiet "${NOCONFIG[@]}" --scanners vuln --format json ${src[@]+"${src[@]}"} ${plat[@]+"${plat[@]}"} "$ref" >"$OUT/$base.json"; then
      failed "$label" "scan failed"
      continue
    fi
    # the image Trivy read must be the platform asked for
    if [ -n "$platform" ]; then
      want_arch="${platform#*/}"
      want="${platform%%/*}/${want_arch%%/*}"
      got="$(image_config "$OUT/$base.json" os)/$(image_config "$OUT/$base.json" architecture)"
      if [ "$got" != "$want" ]; then
        failed "$label" "scan failed: the image is $got"
        continue
      fi
    fi
    if ! trivy_run convert "${NOCONFIG[@]}" --scanners vuln --format table "$(report "$base.json")" >"$OUT/$base.txt"; then
      failed "$label" "report failed"
      continue
    fi
    if ! findings="$(trivy_run convert "${NOCONFIG[@]}" --format template --template "$FINDINGS" "$(report "$base.json")")"; then
      failed "$label" "report failed"
      continue
    fi
    count() { printf '%s\n' "$findings" | awk -F'\t' -v s="$1" -v f="${2:-}" '$1 == s && (f == "" || $2 == f) { n++ } END { print n + 0 }'; }
    fixable="$(printf '%s\n' "$findings" | awk -F'\t' '($1 == "HIGH" || $1 == "CRITICAL") && $2 == "fixed"')"
    cells=""
    for s in CRITICAL HIGH MEDIUM LOW UNKNOWN; do
      cells="$cells $(count "$s") ($(count "$s" fixed)) |"
    done
    # the gate – as in the release: high and critical with a fixed version (the database of the scan above); its
    # answer must agree with the full report
    gate="passed"
    if out="$(trivy_run image --quiet "${NOCONFIG[@]}" --skip-db-update --scanners vuln --severity HIGH,CRITICAL --ignore-unfixed --exit-code 1 --format table ${src[@]+"${src[@]}"} ${plat[@]+"${plat[@]}"} "$ref")"; then
      if [ -n "$fixable" ]; then
        failed "$label" "gate passed, but the full report has fixable high or critical findings"
        continue
      fi
    elif [ -n "$fixable" ]; then
      gate="**FAILED**"
      [ "$status" -eq 2 ] || status=1
      printf '%s\n' "$out"
      blocked="$blocked"$'\n'"### \`$label\`"$'\n\n'"| Severity | Package | Installed | Fixed in | ID |"$'\n'"|---|---|---|---|---|"$'\n'
      blocked="$blocked$(printf '%s\n' "$fixable" | awk -F'\t' '{ printf "| %s | %s | %s | %s | %s |\n", $1, $3, $4, $5, $6 }' | sort -u)"$'\n'
    else
      failed "$label" "gate scan failed"
      continue
    fi
    echo "   critical/high/medium/low/unknown (with a fix):$cells gate: $gate"
    rows="$rows| \`$label\` |$cells $gate |"$'\n'
  done
done

version="$(trivy_run version 2>/dev/null | awk '/^Version:/ { v = $2 } /UpdatedAt:/ && !d { d = $2 " " substr($3, 1, 5) " UTC" } END { printf "Trivy %s, vulnerability database of %s", v, d }' || true)"
{
  echo "# Image scan – $(date -u +%Y-%m-%dT%H:%MZ)"
  echo
  echo "$version."
  echo
  echo "Each cell: all findings (in brackets: those with a fixed version). The gate fails on a fixable high or critical"
  echo "finding; findings without a fix are listed in the full reports (trivy-*.txt, trivy-*.json) and do not fail."
  echo
  echo "| Image | Critical | High | Medium | Low | Unknown | Gate |"
  echo "|---|---|---|---|---|---|---|"
  printf '%s' "$rows"
  if [ -n "$blocked" ]; then
    echo
    echo "## Fixable high and critical findings"
    printf '%s' "$blocked"
  fi
} >"$OUT/summary.md"
echo
cat "$OUT/summary.md"
echo
echo "reports: $OUT"
exit "$status"
