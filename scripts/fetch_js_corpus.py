"""Fetch real-world minified libraries via npm into tests/.cache/js-corpus.

Run before the test suite (CI does this). Tests that need the corpus skip with a clear
reason when it is absent, so the test suite itself never touches the network.

    python scripts/fetch_js_corpus.py
"""

from __future__ import annotations

import shutil
import subprocess  # nosec B404 - runs the local npm executable with fixed arguments
import sys
import tarfile
import tempfile
from pathlib import Path

CACHE = Path(__file__).resolve().parents[1] / "tests" / ".cache" / "js-corpus"
PACKAGES = {
    "jquery@3.7.1": ["package/dist/jquery.min.js"],
    "react@18.3.1": ["package/umd/react.production.min.js"],
    "react-dom@18.3.1": ["package/umd/react-dom.production.min.js"],
}


def main() -> int:
    npm = shutil.which("npm")
    if npm is None:
        print("npm is not installed; cannot fetch the corpus", file=sys.stderr)
        return 1
    CACHE.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as tmp:
        for spec, members in PACKAGES.items():
            if all((CACHE / Path(m).name).exists() for m in members):
                print(f"cached  {spec}")
                continue
            subprocess.run(  # nosec B603 - fixed arguments, no shell
                [npm, "pack", spec, "--silent", "--pack-destination", tmp],
                check=True,
                capture_output=True,
            )
            tarball = next(Path(tmp).glob(f"{spec.split('@')[0]}-*.tgz"))
            with tarfile.open(tarball) as archive:
                for member in members:
                    source = archive.extractfile(member)
                    if source is None:
                        raise SystemExit(f"{member} missing from {spec}")
                    (CACHE / Path(member).name).write_bytes(source.read())
            tarball.unlink()
            print(f"fetched {spec}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
