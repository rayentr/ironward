#!/bin/sh
# Ironward GitHub Action entrypoint.
# POSIX-compatible (sh, not bash).
set -eu

# ─────────────────────────────────────────────────────────────
# Inputs — GitHub Actions passes action inputs as INPUT_*.
# ─────────────────────────────────────────────────────────────
PATH_TO_SCAN="${INPUT_PATH:-.}"
FAIL_ON="${INPUT_FAIL_ON:-high}"
SCAN_SECRETS="${INPUT_SCAN_SECRETS:-true}"
SCAN_CODE="${INPUT_SCAN_CODE:-true}"
SCAN_DEPS="${INPUT_SCAN_DEPS:-true}"
SCAN_URL="${INPUT_SCAN_URL:-}"
ANTHROPIC_KEY="${INPUT_ANTHROPIC_API_KEY:-}"
OPENAI_KEY="${INPUT_OPENAI_API_KEY:-}"
REPORT_PATH="${INPUT_REPORT_PATH:-ironward-report.json}"
# fail-on-new-only is accepted but not yet implemented; we document it for forward-compat.
FAIL_ON_NEW_ONLY="${INPUT_FAIL_ON_NEW_ONLY:-false}"

# Default GITHUB_OUTPUT / GITHUB_STEP_SUMMARY so the script is runnable outside Actions.
: "${GITHUB_OUTPUT:=/tmp/ironward-outputs}"
: "${GITHUB_STEP_SUMMARY:=/tmp/ironward-summary}"
: "${GITHUB_WORKSPACE:=$PWD}"
touch "$GITHUB_OUTPUT" "$GITHUB_STEP_SUMMARY" 2>/dev/null || true

cd "$GITHUB_WORKSPACE"

# ─────────────────────────────────────────────────────────────
# Mask any API key so it never leaks into logs.
# ─────────────────────────────────────────────────────────────
if [ -n "$ANTHROPIC_KEY" ]; then
  echo "::add-mask::$ANTHROPIC_KEY"
fi
if [ -n "$OPENAI_KEY" ]; then
  echo "::add-mask::$OPENAI_KEY"
fi

# ─────────────────────────────────────────────────────────────
# Optionally configure Ironward AI provider.
# (AI scans aren't invoked by this action yet — the config is written
#  so future versions / manual `ironward` calls pick it up.)
# ─────────────────────────────────────────────────────────────
mkdir -p "$HOME/.ironward"
if [ -n "$ANTHROPIC_KEY" ]; then
  printf '{"provider":"anthropic","apiKey":"%s","model":"claude-opus-4-5"}\n' \
    "$ANTHROPIC_KEY" > "$HOME/.ironward/config.json"
  chmod 600 "$HOME/.ironward/config.json"
elif [ -n "$OPENAI_KEY" ]; then
  printf '{"provider":"openai","apiKey":"%s","model":"gpt-4o"}\n' \
    "$OPENAI_KEY" > "$HOME/.ironward/config.json"
  chmod 600 "$HOME/.ironward/config.json"
fi

IRONWARD_VERSION="$(ironward --version 2>/dev/null || echo unknown)"
echo "Ironward $IRONWARD_VERSION — scanning $PATH_TO_SCAN"

# ─────────────────────────────────────────────────────────────
# Collect individual scanner outputs, then merge with jq.
# ─────────────────────────────────────────────────────────────
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

SECRETS_JSON="$WORK/secrets.json"
CODE_JSON="$WORK/code.json"
DEPS_JSON="$WORK/deps.json"
URL_JSON="$WORK/url.json"

EMPTY='{"tool":null,"files":[],"findings":[],"intel":[]}'

if [ "$SCAN_SECRETS" = "true" ]; then
  if ! ironward scan-secrets --format json "$PATH_TO_SCAN" > "$SECRETS_JSON" 2>"$WORK/secrets.err"; then
    # Non-zero exit is expected when findings exist — keep output if it parses.
    if ! jq -e . "$SECRETS_JSON" >/dev/null 2>&1; then
      echo "scan-secrets failed:" >&2
      cat "$WORK/secrets.err" >&2 || true
      echo "$EMPTY" > "$SECRETS_JSON"
    fi
  fi
else
  echo "$EMPTY" > "$SECRETS_JSON"
fi

if [ "$SCAN_CODE" = "true" ]; then
  if ! ironward scan-code --format json "$PATH_TO_SCAN" > "$CODE_JSON" 2>"$WORK/code.err"; then
    if ! jq -e . "$CODE_JSON" >/dev/null 2>&1; then
      echo "scan-code failed:" >&2
      cat "$WORK/code.err" >&2 || true
      echo "$EMPTY" > "$CODE_JSON"
    fi
  fi
else
  echo "$EMPTY" > "$CODE_JSON"
fi

if [ "$SCAN_DEPS" = "true" ]; then
  if ! ironward scan-deps --format json "$PATH_TO_SCAN" > "$DEPS_JSON" 2>"$WORK/deps.err"; then
    if ! jq -e . "$DEPS_JSON" >/dev/null 2>&1; then
      echo "scan-deps failed:" >&2
      cat "$WORK/deps.err" >&2 || true
      echo "$EMPTY" > "$DEPS_JSON"
    fi
  fi
else
  echo "$EMPTY" > "$DEPS_JSON"
fi

if [ -n "$SCAN_URL" ]; then
  if ! ironward scan-url --format json "$SCAN_URL" > "$URL_JSON" 2>"$WORK/url.err"; then
    if ! jq -e . "$URL_JSON" >/dev/null 2>&1; then
      echo "scan-url failed:" >&2
      cat "$WORK/url.err" >&2 || true
      echo '{"tool":"scan_url","findings":[]}' > "$URL_JSON"
    fi
  fi
else
  echo '{"tool":"scan_url","findings":[]}' > "$URL_JSON"
fi

# ─────────────────────────────────────────────────────────────
# Normalize into a common findings shape with jq:
#   { severity, tool, file, line, title, description }
# ─────────────────────────────────────────────────────────────
jq -n --slurpfile s "$SECRETS_JSON" \
      --slurpfile c "$CODE_JSON" \
      --slurpfile d "$DEPS_JSON" \
      --slurpfile u "$URL_JSON" \
      --arg version "$IRONWARD_VERSION" \
      --arg path "$PATH_TO_SCAN" \
      --arg url "$SCAN_URL" \
'
def flatten_secrets(o):
  (o.files // []) | map(
    .path as $p | (.findings // []) | map({
      severity: (.severity // "medium"),
      tool: "scan_for_secrets",
      file: $p,
      line: (.line // 1),
      title: (.type // "secret"),
      description: (.description // .type // "Secret detected")
    })
  ) | add // [];

def flatten_code(o):
  (o.files // []) | map(
    .path as $p | (.findings // []) | map({
      severity: (.severity // "medium"),
      tool: "scan_code",
      file: $p,
      line: (.line // 1),
      title: (.title // "static analysis"),
      description: (.rationale // .title // "Code issue")
    })
  ) | add // [];

def flatten_deps(o):
  ((o.findings // []) | map({
    severity: (.severity // "medium"),
    tool: "scan_deps",
    file: (.source // "package.json"),
    line: 1,
    title: ((.package // "dep") + "@" + (.version // "?") + " — " + (.vulnerabilityId // "vuln")),
    description: (.summary // "Vulnerable dependency")
  }))
  + ((o.intel // []) | map({
    severity: (.severity // "medium"),
    tool: "scan_deps",
    file: (.source // "package.json"),
    line: 1,
    title: ((.kind // "intel") + ": " + (.package // "dep")),
    description: (.summary // "Supply-chain finding")
  }));

def flatten_url(o):
  (o.findings // []) | map({
    severity: (if .severity == "info" then "low" else (.severity // "medium") end),
    tool: "scan_url",
    file: "(url)",
    line: 1,
    title: (.title // .id // "URL issue"),
    description: (.evidence // .title // "URL issue")
  });

def score(all):
  100 - (all | map(
    if .severity == "critical" then 25
    elif .severity == "high" then 12
    elif .severity == "medium" then 5
    elif .severity == "low" then 2
    else 0 end
  ) | add // 0) | if . < 0 then 0 else . end;

(flatten_secrets($s[0]) + flatten_code($c[0]) + flatten_deps($d[0]) + flatten_url($u[0])) as $all |
{
  version: $version,
  path: $path,
  url: $url,
  generatedAt: (now | todate),
  score: score($all),
  counts: {
    critical: ($all | map(select(.severity == "critical")) | length),
    high:     ($all | map(select(.severity == "high"))     | length),
    medium:   ($all | map(select(.severity == "medium"))   | length),
    low:      ($all | map(select(.severity == "low"))      | length),
    total:    ($all | length)
  },
  findings: $all,
  raw: { secrets: $s[0], code: $c[0], deps: $d[0], url: $u[0] }
}
' > "$REPORT_PATH"

# ─────────────────────────────────────────────────────────────
# Counts + outputs.
# ─────────────────────────────────────────────────────────────
TOTAL="$(jq -r '.counts.total // 0' "$REPORT_PATH")"
CRIT="$(jq -r '.counts.critical // 0' "$REPORT_PATH")"
HIGH="$(jq -r '.counts.high // 0' "$REPORT_PATH")"
MED="$(jq -r '.counts.medium // 0' "$REPORT_PATH")"
LOW="$(jq -r '.counts.low // 0' "$REPORT_PATH")"
SCORE="$(jq -r '.score // 0' "$REPORT_PATH")"

{
  echo "findings-count=$TOTAL"
  echo "critical-count=$CRIT"
  echo "high-count=$HIGH"
  echo "medium-count=$MED"
  echo "low-count=$LOW"
  echo "score=$SCORE"
  echo "report-path=$REPORT_PATH"
} >> "$GITHUB_OUTPUT"

# ─────────────────────────────────────────────────────────────
# Job summary.
# ─────────────────────────────────────────────────────────────
{
  printf '## Ironward Security Report\n\n'
  printf '| Metric | Value |\n|---|---|\n'
  printf '| Security Score | **%s**/100 |\n' "$SCORE"
  printf '| Critical | %s |\n' "$CRIT"
  printf '| High | %s |\n' "$HIGH"
  printf '| Medium | %s |\n' "$MED"
  printf '| Low | %s |\n' "$LOW"
  printf '| Total | %s |\n\n' "$TOTAL"

  if [ "$TOTAL" -gt 0 ]; then
    printf '### Findings\n\n'
    printf '| Severity | Tool | File | Line | Title |\n|---|---|---|---|---|\n'
    jq -r '.findings[] |
      "| " + (.severity | ascii_upcase) +
      " | " + .tool +
      " | `" + .file + "`" +
      " | " + (.line | tostring) +
      " | " + (.title | gsub("\\|"; "\\|")) +
      " |"' "$REPORT_PATH" | head -200
    printf '\n'
    if [ "$TOTAL" -gt 200 ]; then
      printf '_(showing first 200 of %s findings — full list in %s)_\n\n' "$TOTAL" "$REPORT_PATH"
    fi
  else
    printf '_No findings._\n\n'
  fi

  printf '\n---\n*Scanned by [Ironward](https://github.com/rayentr/ironward) %s*\n' \
    "$IRONWARD_VERSION"
} >> "$GITHUB_STEP_SUMMARY"

# ─────────────────────────────────────────────────────────────
# Inline annotations on findings.
# ─────────────────────────────────────────────────────────────
jq -r '.findings[] |
  (if .severity == "critical" or .severity == "high" then "error"
   elif .severity == "medium" then "warning"
   else "notice" end) as $level |
  "::" + $level +
  " file=" + .file +
  ",line=" + (.line | tostring) +
  ",title=" + (.severity | ascii_upcase) + ": " + (.title | gsub("\n"; " ")) +
  "::" + (.description | gsub("\n"; " "))' "$REPORT_PATH" || true

# ─────────────────────────────────────────────────────────────
# Determine exit code from fail-on.
# ─────────────────────────────────────────────────────────────
SHOULD_FAIL=0
case "$FAIL_ON" in
  never)
    SHOULD_FAIL=0
    ;;
  critical)
    if [ "$CRIT" -gt 0 ]; then SHOULD_FAIL=1; fi
    ;;
  high)
    if [ "$CRIT" -gt 0 ] || [ "$HIGH" -gt 0 ]; then SHOULD_FAIL=1; fi
    ;;
  medium)
    if [ "$CRIT" -gt 0 ] || [ "$HIGH" -gt 0 ] || [ "$MED" -gt 0 ]; then SHOULD_FAIL=1; fi
    ;;
  low)
    if [ "$TOTAL" -gt 0 ]; then SHOULD_FAIL=1; fi
    ;;
  *)
    echo "unknown fail-on value: $FAIL_ON — defaulting to 'high'" >&2
    if [ "$CRIT" -gt 0 ] || [ "$HIGH" -gt 0 ]; then SHOULD_FAIL=1; fi
    ;;
esac

if [ "$SHOULD_FAIL" = "1" ]; then
  echo "Ironward: failing build — $CRIT critical, $HIGH high, $MED medium, $LOW low findings (fail-on=$FAIL_ON)."
  exit 1
fi
echo "Ironward: passing — $TOTAL findings, none exceed fail-on=$FAIL_ON."
exit 0
