#!/usr/bin/env bash
set -euo pipefail

commit_file() {
  local file="$1"
  local message="$2"

  if [[ ! -e "$file" ]]; then
    echo "skip: $file does not exist"
    return
  fi

  git add -- "$file"

  if git diff --cached --quiet -- "$file"; then
    git reset -q -- "$file"
    echo "skip: no staged changes for $file"
    return
  fi

  git commit -m "$message"
}

commit_file "backend/graph/graph_builder.py" "fix: export scoped graph state for frontend"
commit_file "backend/graph/queries.py" "security: scope graph helper queries by investigation"
commit_file "backend/main.py" "feat: add text investigations and subsystem health"
commit_file "backend/models.py" "feat: add text investigation request model"
commit_file "backend/nlq/query_engine.py" "fix: report empty RAG retrieval honestly"
commit_file "backend/tests/test_parser_graph_nlq.py" "test: extend parser graph and RAG regressions"
commit_file "frontend/src/api.js" "feat: add text investigation API client"
commit_file "frontend/src/components/Dashboard.jsx" "feat: enrich investigation console views"
commit_file "frontend/src/components/FileUpload.jsx" "feat: add investigation input wizard"
commit_file "frontend/src/components/QueryBar.jsx" "feat: show query grounding sources"
commit_file "frontend/src/index.css" "style: add console controls and archive styles"
commit_file "commit.sh" "chore: update per-file commit helper"

