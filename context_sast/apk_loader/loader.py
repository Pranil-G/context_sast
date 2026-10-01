from __future__ import annotations

import hashlib
from pathlib import Path

from context_sast.models import LoadedApk


class ApkIntegrityError(RuntimeError):
    """The APK changed on disk between fingerprinting and the end of the scan."""


class ApkLoader:
    CHUNK_BYTES = 1024 * 1024

    def load(self, apk_path: str | Path) -> LoadedApk:
        path = Path(apk_path).resolve()
        if not path.exists():
            raise FileNotFoundError(f"APK not found: {path}")
        if path.suffix.lower() != ".apk":
            raise ValueError(f"Expected an .apk file, got: {path.name}")

        stat = path.stat()
        return LoadedApk(
            path=path,
            sha256=self._digest(path),
            size_bytes=stat.st_size,
            mtime_ns=stat.st_mtime_ns,
        )

    def verify_unchanged(self, loaded: LoadedApk) -> None:
        """Confirm the analysed file is still the one that was fingerprinted.

        A scan reads the APK repeatedly: Androguard parses it, and the evidence
        pass hands the same path to jadx. Between those reads the file can be
        replaced -- most plausibly in the dashboard, where an upload is written
        to a shared temporary directory, but equally in a batch run over a
        directory someone else is writing to. Reporting findings from binary A
        under the name of binary B would be worse than failing, so the digest
        taken at load time is checked again here.

        Size and modification time are compared first because they are a stat
        call; the file is only re-hashed when one of them moved, which keeps the
        common case free.
        """
        if not loaded.path.exists():
            raise ApkIntegrityError(f"APK disappeared during the scan: {loaded.path}")

        stat = loaded.path.stat()
        if stat.st_size == loaded.size_bytes and stat.st_mtime_ns == loaded.mtime_ns:
            return

        current = self._digest(loaded.path)
        if current != loaded.sha256:
            raise ApkIntegrityError(
                f"APK changed during the scan: {loaded.path}\n"
                f"  fingerprinted: sha256={loaded.sha256} size={loaded.size_bytes}\n"
                f"  now:           sha256={current} size={stat.st_size}"
            )

    def _digest(self, path: Path) -> str:
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(self.CHUNK_BYTES), b""):
                digest.update(chunk)
        return digest.hexdigest()
