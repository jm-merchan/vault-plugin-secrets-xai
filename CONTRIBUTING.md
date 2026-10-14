# Contributing

## Pull requests

1. Branch from `main` (`feature/...` or `fix/...`).
2. Keep commits focused; do not force-push `main`.
3. Open a PR and wait for review / CI before merging.
4. Prefer `gh pr create` / Cursor Origin PR flow over pushing directly to `main`.

This repo ships Cursor project hooks under `.cursor/` that:

- inject current branch / open-PR context at session start
- ask before force-push, hard reset, direct push to `main`, or `gh pr merge|close`
- nudge a PR follow-up when the agent stops on a feature branch
