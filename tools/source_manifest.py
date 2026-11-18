"""Hash reproducibility inputs without credentials, host paths, or outputs."""
import hashlib
from pathlib import Path


def source_manifest(root):
    root = Path(root)
    paths = set()
    for pattern in (
        "lab/**/*.py", "tools/**/*.py", "tests/**/*.py",
        "architecture/*.json", "examples/**/*.json", "Dockerfile",
    ):
        paths.update(path for path in root.glob(pattern) if path.is_file())
    return {path.relative_to(root).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in sorted(paths)}
