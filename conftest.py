"""Pytest bootstrap for repository-level test runs."""
import sys
from pathlib import Path


ROOT_DIR = Path(__file__).resolve().parent
TESTS_DIR = ROOT_DIR / "tests"
BACKEND_DIR = ROOT_DIR / "backend"

for path in (TESTS_DIR, BACKEND_DIR):
    path_str = str(path)
    if path_str not in sys.path:
        sys.path.insert(0, path_str)
