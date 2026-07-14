import os
import stat
from pathlib import Path

import pytest

FAKE_CCC_SCRIPT = """#!/bin/sh
cat <<'EOF'

--- Result 1 (score: 0.900) ---
File: app/db.py:6-6 [python]
    cursor.execute(f"SELECT * FROM users WHERE name = '{name}'")
EOF
"""

FAKE_CCC_TWO_RESULTS_SCRIPT = """#!/bin/sh
cat <<'EOF'

--- Result 1 (score: 0.900) ---
File: app/other.py:1-1 [python]
    clean code, no finding here

--- Result 2 (score: 0.850) ---
File: app/db.py:6-6 [python]
    cursor.execute(f"SELECT * FROM users WHERE name = '{name}'")
EOF
"""

FAKE_CCC_ERROR_SCRIPT = """#!/bin/sh
echo 'ccc service failed' >&2
exit 42
"""

FAKE_CCC_ARGS_RECORDING_SCRIPT = """#!/bin/sh
echo ""
echo "--- Result 1 (score: 0.900) ---"
echo "File: app/db.py:6-6 [python]"
echo "ARGS:$*"
"""

FAKE_CCC_HANGING_SCRIPT = """#!/bin/sh
sleep 5
"""


def install_fake_ccc(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, script_content: str
) -> Path:
    """Place un faux binaire `ccc` en tête de PATH, à sortie déterministe."""
    bin_dir = tmp_path / "fake_bin"
    bin_dir.mkdir()
    script = bin_dir / "ccc"
    script.write_text(script_content)
    script.chmod(script.stat().st_mode | stat.S_IEXEC)
    monkeypatch.setenv("PATH", f"{bin_dir}:{os.environ.get('PATH', '')}")
    index_path = tmp_path / ".cocoindex_code" / "target_sqlite.db"
    index_path.parent.mkdir(parents=True, exist_ok=True)
    index_path.write_text("")
    return bin_dir


@pytest.fixture
def fake_ccc_on_path(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    return install_fake_ccc(tmp_path, monkeypatch, FAKE_CCC_SCRIPT)


@pytest.fixture
def fake_ccc_two_results_on_path(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    return install_fake_ccc(tmp_path, monkeypatch, FAKE_CCC_TWO_RESULTS_SCRIPT)


@pytest.fixture
def fake_ccc_error_on_path(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    return install_fake_ccc(tmp_path, monkeypatch, FAKE_CCC_ERROR_SCRIPT)


@pytest.fixture
def fake_ccc_args_recording_on_path(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Faux `ccc` qui renvoie les arguments reçus dans le contenu du résultat
    (`ARGS:...`), pour vérifier que les flags sont transmis tels quels."""
    return install_fake_ccc(tmp_path, monkeypatch, FAKE_CCC_ARGS_RECORDING_SCRIPT)


@pytest.fixture
def fake_ccc_hanging_on_path(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    return install_fake_ccc(tmp_path, monkeypatch, FAKE_CCC_HANGING_SCRIPT)


@pytest.fixture
def no_ccc_on_path(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """PATH minimal sans `ccc` (conserve un shell utilisable)."""
    empty = tmp_path / "empty_bin"
    empty.mkdir()
    monkeypatch.setenv("PATH", str(empty))
