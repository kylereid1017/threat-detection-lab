"""Read a rule corpus out of git object storage without writing it to disk.

A public Sigma corpus is thousands of files full of live command-line strings,
encoded payload fragments, and download cradles. Checking one out onto a
workstation running endpoint protection is asking for a partial corpus: files get
quarantined mid-analysis, the count silently drops, and the resulting measurement
is wrong in a direction nobody notices. That is not hypothetical here. This
repository already lost a documentation file to exactly that mechanism.

A bare clone stores everything as compressed objects in a packfile. No rule text
is ever written to the filesystem in a form a scanner matches, and the contents
are streamed through `git cat-file --batch` into memory for analysis.

The count of objects listed and the count successfully read are both reported, so
a corpus that does go short says so instead of quietly producing a clean number.
"""

from __future__ import annotations

import os
import shutil
import stat
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterator, List, Optional, Sequence, Tuple


class CorpusError(RuntimeError):
    """The corpus could not be retrieved or read."""


def _force_rmtree(path: Path) -> None:
    def _on_error(func, target, _exc_info):
        try:
            os.chmod(target, stat.S_IWRITE)
            func(target)
        except OSError:
            pass

    if path.exists():
        shutil.rmtree(path, onerror=_on_error)


def _git(args: Sequence[str], cwd: Optional[Path] = None, timeout: int = 900) -> str:
    try:
        result = subprocess.run(
            ["git", *args],
            cwd=str(cwd) if cwd else None,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except FileNotFoundError as exc:
        raise CorpusError("git is not available on PATH") from exc
    except subprocess.TimeoutExpired as exc:
        raise CorpusError(f"git timed out after {timeout}s") from exc
    if result.returncode != 0:
        raise CorpusError(f"git {' '.join(args)} failed: {result.stderr.strip()[:300]}")
    return result.stdout


@dataclass
class CorpusRead:
    """What a corpus read produced, including what it could not read."""

    files: List[Tuple[str, str]] = field(default_factory=list)
    listed: int = 0
    unreadable: int = 0
    source: str = ""
    revision: str = ""

    def to_dict(self) -> Dict[str, object]:
        return {
            "source": self.source,
            "revision": self.revision,
            "files_listed": self.listed,
            "files_read": len(self.files),
            "files_unreadable": self.unreadable,
            "read_note": (
                "Contents were streamed from git object storage. No rule text was "
                "written to the filesystem."
            ),
        }


def _batch_read(repo: Path, paths: Sequence[str]) -> Iterator[Tuple[str, str]]:
    """Stream blob contents for `paths` via a single `git cat-file --batch`."""
    if not paths:
        return
    request = "".join(f"HEAD:{p}\n" for p in paths).encode("utf-8")
    try:
        process = subprocess.run(
            ["git", "cat-file", "--batch"],
            cwd=str(repo),
            input=request,
            capture_output=True,
            timeout=1800,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise CorpusError("git cat-file timed out") from exc
    if process.returncode != 0:
        raise CorpusError(f"git cat-file failed: {process.stderr.decode(errors='replace')[:300]}")

    stream = process.stdout
    offset = 0
    index = 0
    total = len(stream)
    while offset < total and index < len(paths):
        newline = stream.find(b"\n", offset)
        if newline == -1:
            break
        header = stream[offset:newline].decode("utf-8", errors="replace")
        offset = newline + 1
        parts = header.split()
        if len(parts) < 3 or parts[1] != "blob":
            # "<name> missing" or a non-blob object; skip and keep the path
            # alignment by advancing the index.
            index += 1
            continue
        size = int(parts[2])
        body = stream[offset : offset + size]
        offset += size + 1  # trailing newline after the object body
        yield paths[index], body.decode("utf-8", errors="replace")
        index += 1


def read_rule_corpus(
    url: str,
    path_prefix: str = "",
    suffixes: Sequence[str] = (".yml", ".yaml"),
    workdir: Optional[Path] = None,
) -> CorpusRead:
    """Bare-clone `url` and stream matching rule files into memory."""
    destination = workdir or (Path(tempfile.gettempdir()) / "tdl-rule-corpus")
    _force_rmtree(destination)
    destination.parent.mkdir(parents=True, exist_ok=True)
    try:
        _git(["clone", "--bare", "--depth", "1", url, str(destination)])
        revision = _git(["rev-parse", "HEAD"], cwd=destination).strip()
        listing = _git(["ls-tree", "-r", "--name-only", "HEAD"], cwd=destination)
        wanted = [
            line
            for line in listing.splitlines()
            if line.endswith(tuple(suffixes)) and line.startswith(path_prefix)
        ]
        read = CorpusRead(listed=len(wanted), source=url, revision=revision)
        for name, text in _batch_read(destination, wanted):
            read.files.append((name, text))
        read.unreadable = read.listed - len(read.files)
        if not read.files:
            raise CorpusError(
                f"no files matched prefix '{path_prefix}' with suffixes {suffixes}"
            )
        return read
    finally:
        _force_rmtree(destination)
