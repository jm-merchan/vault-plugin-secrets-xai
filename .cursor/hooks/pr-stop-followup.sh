#!/usr/bin/env bash
# On agent stop, nudge PR workflow when the branch has unpushed work or an open PR.
set -euo pipefail

input=$(cat)
status=$(echo "$input" | jq -r '.status // empty')
loop_count=$(echo "$input" | jq -r '.loop_count // 0')

# Only follow up once per stop chain, and only on clean completion
if [[ "$status" != "completed" ]]; then
  echo '{}'
  exit 0
fi
if [[ "${loop_count:-0}" -ge 1 ]]; then
  echo '{}'
  exit 0
fi

cd "$(git rev-parse --show-toplevel 2>/dev/null)" || { echo '{}'; exit 0; }

branch=$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo "")
if [[ -z "$branch" || "$branch" == "HEAD" ]]; then
  echo '{}'
  exit 0
fi

msg=""

# Open PR for current branch?
pr_url=""
if command -v gh >/dev/null 2>&1; then
  pr_url=$(gh pr view --json url -q .url 2>/dev/null || true)
fi

ahead=0
if git rev-parse --abbrev-ref '@{u}' >/dev/null 2>&1; then
  ahead=$(git rev-list --count '@{u}..HEAD' 2>/dev/null || echo 0)
else
  # No upstream — treat local commits as needing push/PR if not main
  ahead=$(git rev-list --count "main..HEAD" 2>/dev/null || git rev-list --count HEAD 2>/dev/null || echo 0)
fi

dirty=$(git status --porcelain 2>/dev/null | wc -l | tr -d ' ')

if [[ -n "$pr_url" ]]; then
  if [[ "$ahead" -gt 0 ]]; then
    msg="Branch \`${branch}\` has ${ahead} commit(s) not on the remote tracking branch. Push and update the open PR: ${pr_url}"
  elif [[ "$dirty" -gt 0 ]]; then
    msg="There are uncommitted changes on \`${branch}\` with open PR ${pr_url}. Commit (if requested) and push so the PR stays current."
  else
    # Soft reminder only when PR exists and work just finished
    msg="Open PR for \`${branch}\`: ${pr_url}. Check CI / review comments if the user wants next steps."
  fi
elif [[ "$branch" != "main" && "$branch" != "master" ]]; then
  if [[ "$ahead" -gt 0 || "$dirty" -gt 0 ]]; then
    msg="You are on feature branch \`${branch}\` with local changes or commits ahead of main. If the user wants a PR, push the branch and run \`gh pr create\` (or Origin equivalent)."
  fi
fi

if [[ -z "$msg" ]]; then
  echo '{}'
  exit 0
fi

jq -n --arg m "$msg" '{followup_message:$m}'
exit 0
