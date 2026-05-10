"""RAPTOR background worker entrypoint.

Run this as a separate container process when RAPTOR_PROCESS_ROLE=worker.
The API process handles HTTP; this process handles investigation jobs and the
optional Elasticsearch poller.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))

from pipeline_runner import run_worker_process

if __name__ == "__main__":
    run_worker_process()
