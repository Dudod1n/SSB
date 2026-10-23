#!/usr/bin/env python3
"""Read-only checks of the native CLI's public files, index and Git history."""

import argparse
import os
from pathlib import Path
import re
import subprocess
import sys


PUBLIC_FILES = {
    ".gitignore", "README.md", "CONTRIBUTING.md", "REVIEW.md", "go.mod",
    ".github/PULL_REQUEST_TEMPLATE.md", ".github/workflows/ci.yml",
    "scripts/check-publication.py", "tests/test_publication.py",
}
SECRET_PATTERNS = {
    "закрытый ключ": rb"-----BEGIN (?:[A-Z0-9]+ )?PRIVATE KEY-----",
    "GitHub token": rb"\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})",
    "AWS access key": rb"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b",
    "Slack token": rb"\bxox[baprs]-[A-Za-z0-9-]{20,}",
    "API key": rb"\bsk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{24,}",
}


def allowed(path):
    # Keep the former path valid when checking published history.
    return path in PUBLIC_FILES or (path.startswith(("cmd/ssb/", "cmd/network-inspect/"))
                                   and path.endswith(".go") and path.count("/") == 2)


def check(repo, revision):
    env = dict(os.environ, GIT_NO_REPLACE_OBJECTS="1")
    for key in ("GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE", "GIT_OBJECT_DIRECTORY",
                "GIT_ALTERNATE_OBJECT_DIRECTORIES"):
        env.pop(key, None)

    def git(*args):
        return subprocess.run(["git", "-C", str(repo), *args], check=True,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env).stdout

    if Path(os.fsdecode(git("rev-parse", "--show-toplevel")).strip()).resolve() != repo.resolve():
        raise ValueError("--repo должен указывать на корень публичной рабочей копии")
    if git("rev-parse", "--is-shallow-repository").strip() != b"false":
        raise ValueError("нужна полная история, shallow-копию проверить нельзя")
    for name in ("objects/info/alternates", "info/grafts"):
        path = Path(os.fsdecode(git("rev-parse", "--git-path", name)).strip())
        if not path.is_absolute():
            path = repo / path
        if path.exists() and path.stat().st_size:
            raise ValueError("публичная копия не должна использовать alternates или grafts")
    commit = git("rev-parse", "--verify", "--end-of-options", revision + "^{commit}").strip().decode("ascii")
    findings = set()

    def inspect_content(path, body, location):
        for name, pattern in SECRET_PATTERNS.items():
            match = re.search(pattern, body)
            if match:
                line = body[:match.start()].count(b"\n") + 1
                findings.add(f"{location}: {path}:{line}: {name}")
        try:
            body.decode("utf-8")
            if b"\0" in body:
                raise UnicodeError()
        except UnicodeError:
            findings.add(f"{location}: {path}: двоичный файл вместо публичного исходника")

    def inspect_path(path, mode, body, location):
        if not allowed(path):
            findings.add(f"{location}: {path}: путь не входит в публичный комплект")
        elif mode not in (b"100644", b"100755"):
            findings.add(f"{location}: {path}: ссылка или submodule не разрешены")
        else:
            inspect_content(path, body, location)

    for raw in set(git("ls-files", "--cached", "--others", "--exclude-standard", "-z").split(b"\0")) - {b""}:
        path = os.fsdecode(raw)
        file = repo / path
        if file.is_symlink():
            inspect_path(path, b"120000", b"", "рабочее дерево")
        elif file.exists():
            inspect_path(path, b"100644", file.read_bytes(), "рабочее дерево")

    for entry in git("ls-files", "--stage", "-z").split(b"\0"):
        if not entry:
            continue
        metadata, raw = entry.split(b"\t", 1)
        mode, blob, stage = metadata.split()
        path = os.fsdecode(raw)
        if stage != b"0":
            findings.add(f"индекс: {path}: неразрешённый конфликт")
        else:
            body = git("cat-file", "blob", blob.decode()) if mode != b"160000" else b""
            inspect_path(path, mode, body, "индекс")

    checked = set()
    commits = git("rev-list", commit).splitlines()
    for sha in commits:
        location = "коммит " + sha[:12].decode()
        inspect_content("метаданные коммита", git("cat-file", "commit", sha.decode()), location)
        for entry in git("ls-tree", "-rz", "--full-tree", sha.decode()).split(b"\0"):
            if not entry:
                continue
            metadata, raw = entry.split(b"\t", 1)
            mode, kind, blob = metadata.split()
            if (mode, blob, raw) in checked:
                continue
            checked.add((mode, blob, raw))
            body = git("cat-file", "blob", blob.decode()) if kind == b"blob" else b""
            inspect_path(os.fsdecode(raw), mode, body, location)

    for finding in sorted(findings):
        print(finding)
    print(f"Проверено коммитов: {len(commits)}; замечаний: {len(findings)}. Ref: {commit}.")
    print("Проверка не заменяет просмотр diff, реальных адресов, личных данных и конфигураций.")
    return 1 if findings else 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=Path.cwd())
    parser.add_argument("--revision", default="HEAD", help="точный отправляемый ref или SHA")
    args = parser.parse_args()
    try:
        return check(args.repo.resolve(), args.revision)
    except (OSError, ValueError, subprocess.CalledProcessError):
        print("Проверка не выполнена: проверьте путь к Git-репозиторию, ref и доступность полной истории.", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
