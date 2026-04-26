#!/usr/bin/env bash
set -euo pipefail

declare -A MESSAGES=(
  ["README.md"]="docs: describe live API-backed RAPTOR"
  ["backend/main.py"]="backend: expose investigation metadata for console"
  ["backend/models.py"]="backend: extend investigation response models"
  ["frontend/src/api/raptorApi.js"]="frontend: add RAPTOR API client"
  ["frontend/src/components/Dashboard.jsx"]="frontend: connect console to backend APIs"
  ["frontend/src/data/raptorDemo.js"]="frontend: remove static demo intelligence"
  ["frontend/src/index.css"]="frontend: add live console states"
  ["commit.sh"]="chore: commit changed files separately"
)

FILES=(
  "README.md"
  "backend/main.py"
  "backend/models.py"
  "frontend/src/api/raptorApi.js"
  "frontend/src/components/Dashboard.jsx"
  "frontend/src/data/raptorDemo.js"
  "frontend/src/index.css"
  "commit.sh"
)

for file in "${FILES[@]}"; do
  if [[ -z "$(git status --short -- "$file")" ]]; then
    continue
  fi

  git add -A -- "$file"

  if git diff --cached --quiet -- "$file"; then
    continue
  fi

  git commit -m "${MESSAGES[$file]}"
done

git status --short
