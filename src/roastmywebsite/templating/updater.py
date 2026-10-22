from __future__ import annotations

import tarfile
import urllib.request
import zipfile
from pathlib import Path


def update_templates(url: str, dest: Path | None = None) -> Path:
    dest = dest or (Path.home() / ".config" / "roastmywebsite" / "templates")
    dest.mkdir(parents=True, exist_ok=True)
    archive = dest / "templates_download"
    urllib.request.urlretrieve(url, archive)
    # Try zip
    try:
        with zipfile.ZipFile(archive) as zf:
            for member in zf.namelist():
                target = (dest / member).resolve()
                if not str(target).startswith(str(dest.resolve())):
                    continue
            zf.extractall(dest)
            archive.unlink(missing_ok=True)
            return dest
    except zipfile.BadZipFile:
        pass
    # Try tar
    try:
        with tarfile.open(archive, "r:*") as tf:
            for member in tf.getmembers():
                target = (dest / member.name).resolve()
                if not str(target).startswith(str(dest.resolve())):
                    continue
            tf.extractall(dest)
            archive.unlink(missing_ok=True)
            return dest
    except (tarfile.TarError, OSError):
        archive.unlink(missing_ok=True)
        raise ValueError("Unsupported archive format")