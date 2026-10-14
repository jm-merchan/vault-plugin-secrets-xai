#!/usr/bin/env bash
# Ask before destructive git / GitHub PR operations.
set -euo pipefail

input=$(cat)
command=$(echo "$input" | jq -r '.command // empty')

# Normalize for matching
cmd_lc=$(echo "$command" | tr '[:upper:]' '[:lower:]')

ask() {
  local user_msg="$1"
  local agent_msg="$2"
  jq -n \
    --arg um "$user_msg" \
    --arg am "$agent_msg" \
    '{permission:"ask", user_message:$um, agent_message:$am}'
  exit 0
}

# Force-push to main/master
if [[ "$cmd_lc" =~ (git[[:space:]]+push.*)(--force|--force-with-lease|-f) ]]; then
  if [[ "$cmd_lc" =~ (origin[[:space:]]+)?(main|master) ]] || [[ "$cmd_lc" =~ (HEAD:refs/heads/(main|master)|refs/heads/(main|master)) ]]; then
    ask \
      "Force-push to main/master detected. Confirm before continuing." \
      "Hook blocked automatic force-push to the default branch. Prefer a normal push or an explicit user-approved force."
  fi
  ask \
    "Force-push detected. Confirm before continuing." \
    "A git force-push was requested. Confirm with the user before rewriting remote history."
fi

# Hard reset
if [[ "$cmd_lc" =~ git[[:space:]]+reset[[:space:]]+--hard ]]; then
  ask \
    "git reset --hard detected. Confirm before discarding local changes." \
    "Destructive reset requested. Confirm with the user before discarding work."
fi

# PR merge / close / delete
if [[ "$cmd_lc" =~ gh[[:space:]]+pr[[:space:]]+(merge|close) ]]; then
  ask \
    "GitHub PR merge/close detected. Confirm before changing PR state." \
    "Confirm with the user before merging or closing a pull request."
fi

if [[ "$cmd_lc" =~ gh[[:space:]]+pr[[:space:]]+ready ]] && [[ "$cmd_lc" =~ --undo ]]; then
  ask \
    "Marking PR as draft again. Confirm before continuing." \
    "Confirm before converting a ready PR back to draft."
fi

# Push directly to main/master (not via PR branch)
if [[ "$cmd_lc" =~ git[[:space:]]+push ]] && [[ "$cmd_lc" =~ (^|[[:space:]])(origin[[:space:]]+)?(main|master)([[:space:]]|$) ]]; then
  if [[ ! "$cmd_lc" =~ --force ]]; then
    ask \
      "Direct push to main/master detected. Prefer a feature branch + PR unless this is intentional." \
      "Direct push to the default branch. Confirm with the user; prefer opening a PR from a feature branch."
  fi
fi

echo '{ "permission": "allow" }'
exit 0
