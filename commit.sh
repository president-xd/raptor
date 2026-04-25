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

commit_file "CHECK_THIS_OUT.md" "docs: add RAPTOR production readiness assessment"
commit_file "backend/main.py" "fix: harden API upload bounds and client cleanup"
commit_file "backend/nlq/query_engine.py" "security: enforce scoped read-only NLQ Cypher"
commit_file "backend/rag/indexer.py" "fix: honor Weaviate gRPC port during indexing"
commit_file "backend/rag/retriever.py" "fix: honor Weaviate gRPC port during retrieval"
commit_file "backend/requirements.txt" "chore: pin Weaviate client to v4 API"
commit_file "backend/tests/test_parser_graph_nlq.py" "test: cover parser graph and NLQ safety regressions"
commit_file "commit.sh" "chore: add per-file commit and push helper"

git push "$@"
