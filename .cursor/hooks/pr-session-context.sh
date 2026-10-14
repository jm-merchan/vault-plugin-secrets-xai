#!/usr/bin/env bash
# At session start, tell the agent about the current branch / open PR.
set -euo pipefail

# Consume stdin (sessionStart payload)
cat >/dev/null

cd "$(git rev-parse --show-toplevel 2>/dev/null)" || { echo '{}'; exit 0; }

branch=$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo "")
context="Repo: vault-plugin-secrets-xai (standalone). Prefer feature branches + PRs; do not force-push main."

if [[ -n "$branch" ]]; then
  context="$context Current branch: ${branch}."
fi

if command -v gh >/dev/null 2>&1; then
  pr_json=$(gh pr view --json url,title,state,reviewDecision,statusCheckRollup 2>/dev/null || true)
  if [[ -n "$pr_json" && "$pr_json" != "null" ]]; then
    url=$(echo "$pr_json" | jq -r '.url // empty')
    title=$(echo "$pr_json" | jq -r '.title // empty')
    state=$(echo "$pr_json" | jq -r '.state // empty')
    review=$(echo "$pr_json" | jq -r '.reviewDecision // empty')
    context="$context Open PR: ${title} (${state}) ${url}."
    if [[ -n "$review" && "$review" != "null" ]]; then
      context="$context Review decision: ${review}."
    fi
  fi
fi

jq -n --arg c "$context" '{additional_context:$c}'
exit 0
