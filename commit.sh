#!/usr/bin/env bash
set -euo pipefail

commit_path() {
  local path="$1"
  local message="$2"

  git add -A -- "$path"

  if git diff --cached --quiet -- "$path"; then
    echo "skip: no staged changes for $path"
    return
  fi

  git commit -m "$message"
}

commit_path "frontend/src/components/Dashboard.jsx" "feat: expand investigation dashboard controls"
commit_path "frontend/src/components/QueryBar.jsx" "feat: warn on weak query grounding"
commit_path "frontend/src/index.css" "style: add dashboard control styling"
commit_path "Broken.md" "docs: remove stale broken-items notes"
commit_path "CHECK_THIS_OUT.md" "docs: remove empty check-this-out note"
commit_path "commit.sh" "chore: update targeted commit helper"
