"""
RAPTOR | Evidence Storage Abstraction
Supports local filesystem (default) and S3-compatible object storage.
Switch backends by setting RAPTOR_STORAGE_BACKEND=s3 with matching S3_* env vars.
"""
from __future__ import annotations

import os
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Optional


class StorageBackend(ABC):
    @abstractmethod
    def write(self, relative_key: str, content: bytes) -> str:
        """Persist content and return the canonical location string (path or s3:// URI)."""

    @abstractmethod
    def read(self, location: str) -> bytes:
        """Read content from a canonical location string."""

    @abstractmethod
    def exists(self, location: str) -> bool:
        """Return True if the object at location exists."""

    @abstractmethod
    def delete(self, location: str) -> None:
        """Delete the object at location (no-op if missing)."""


class LocalStorage(StorageBackend):
    def __init__(self, base_dir: Path):
        self._base = Path(base_dir)

    def write(self, relative_key: str, content: bytes) -> str:
        full = self._base / relative_key
        full.parent.mkdir(parents=True, exist_ok=True)
        full.write_bytes(content)
        return str(full)

    def read(self, location: str) -> bytes:
        return Path(location).read_bytes()

    def exists(self, location: str) -> bool:
        return Path(location).exists()

    def delete(self, location: str) -> None:
        p = Path(location)
        if p.exists():
            p.unlink()


class S3Storage(StorageBackend):
    """S3-compatible storage backend (AWS S3, MinIO, GCS interop)."""

    def __init__(
        self,
        bucket: str,
        prefix: str = "evidence/",
        region: str = "us-east-1",
        endpoint_url: str = "",
    ):
        if not bucket:
            raise ValueError("S3_BUCKET must be set when RAPTOR_STORAGE_BACKEND=s3")
        self._bucket = bucket
        self._prefix = prefix.rstrip("/") + "/"
        self._region = region
        self._endpoint_url = endpoint_url or None
        self.__client = None

    def _client(self):
        if self.__client is None:
            import boto3  # type: ignore[import]

            kwargs: dict = {"region_name": self._region}
            if self._endpoint_url:
                kwargs["endpoint_url"] = self._endpoint_url
            self.__client = boto3.client("s3", **kwargs)
        return self.__client

    def _s3_key(self, relative_key: str) -> str:
        return f"{self._prefix}{relative_key.lstrip('/')}"

    def write(self, relative_key: str, content: bytes) -> str:
        key = self._s3_key(relative_key)
        self._client().put_object(
            Bucket=self._bucket,
            Key=key,
            Body=content,
            ServerSideEncryption="AES256",
        )
        return f"s3://{self._bucket}/{key}"

    def read(self, location: str) -> bytes:
        if location.startswith("s3://"):
            rest = location[5:]
            bucket, key = rest.split("/", 1)
        else:
            bucket, key = self._bucket, self._s3_key(location)
        resp = self._client().get_object(Bucket=bucket, Key=key)
        return resp["Body"].read()

    def exists(self, location: str) -> bool:
        try:
            if location.startswith("s3://"):
                rest = location[5:]
                bucket, key = rest.split("/", 1)
            else:
                bucket, key = self._bucket, self._s3_key(location)
            self._client().head_object(Bucket=bucket, Key=key)
            return True
        except Exception:
            return False

    def delete(self, location: str) -> None:
        if location.startswith("s3://"):
            rest = location[5:]
            bucket, key = rest.split("/", 1)
        else:
            bucket, key = self._bucket, self._s3_key(location)
        try:
            self._client().delete_object(Bucket=bucket, Key=key)
        except Exception:
            pass


_storage_instance: Optional[StorageBackend] = None


def get_storage() -> StorageBackend:
    """Return the configured storage backend singleton."""
    global _storage_instance
    if _storage_instance is not None:
        return _storage_instance

    backend = os.getenv("RAPTOR_STORAGE_BACKEND", "local").lower()
    if backend == "s3":
        _storage_instance = S3Storage(
            bucket=os.getenv("S3_BUCKET", ""),
            prefix=os.getenv("S3_PREFIX", "evidence/"),
            region=os.getenv("S3_REGION", "us-east-1"),
            endpoint_url=os.getenv("S3_ENDPOINT_URL", ""),
        )
    else:
        from config import EVIDENCE_DIR
        _storage_instance = LocalStorage(EVIDENCE_DIR)
    return _storage_instance
