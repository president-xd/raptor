#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(git rev-parse --show-toplevel)"
cd "$ROOT_DIR"

git update-index -q --refresh || true

# Per-file commits require a predictable index. This only unstages paths; it
# does not change the working tree.
git reset --quiet

commit_subject() {
  local path="$1"
  local subject

  case "$path" in
    README.md)
      subject="docs: update README"
      ;;
    tests/*|backend/tests/*)
      subject="test: update $path"
      ;;
    backend/*)
      subject="backend: update ${path#backend/}"
      ;;
    frontend/*)
      subject="frontend: update ${path#frontend/}"
      ;;
    .env.example|docker-compose.yml|commit.sh|*Dockerfile)
      subject="chore: update $path"
      ;;
    *)
      subject="chore: update $path"
      ;;
  esac

  printf '%.72s\n' "$subject"
}

mapfile -d '' FILES < <(
  {
    git diff --name-only -z HEAD --
    git ls-files --others --exclude-standard -z
  } | awk -v RS='\0' 'NF && !seen[$0]++ { printf "%s%c", $0, 0 }'
)

if [ "${#FILES[@]}" -eq 0 ]; then
  echo "No changed files to commit."
  exit 0
fi

echo "Creating one commit per changed file..."

for file in "${FILES[@]}"; do
  if [ -z "$file" ]; then
    continue
  fi

  git add -A -- "$file"

  if git diff --cached --quiet -- "$file"; then
    echo "Skipping unchanged path: $file"
    continue
  fi

  subject="$(commit_subject "$file")"
  echo "Committing $file -> $subject"
  git commit -m "$subject"
done

if [ -n "$(git status --porcelain --untracked-files=normal)" ]; then
  echo "Some paths were not committed:"
  git status --short
  exit 1
fi

echo "All changed files were committed individually."
