from pathlib import Path

import numpy as np

from cccf.models import Finding
from cccf.store import Store


def make_finding(
    path: str = "app/db.py",
    rule_id: str = "custom.sql-fstring",
    severity: str = "ERROR",
    suffix: str = "",
) -> Finding:
    return Finding(
        id=f"finding-{path}-{rule_id}{suffix}",
        rule_id=rule_id,
        severity=severity,
        message="Une requête SQL construite par f-string.",
        path=path,
        start_line=6,
        end_line=6,
        snippet='cursor.execute(f"SELECT * FROM users WHERE name = \'{name}\'")',
        fix=None,
        cwe=["CWE-89"],
        owasp=["A03:2021"],
    )


def test_insert_and_reread_finding_roundtrip(tmp_path: Path) -> None:
    finding = make_finding()

    with Store(tmp_path) as store:
        store.replace_findings_for_files(["app/db.py"], [finding])

    with Store(tmp_path) as store:
        results = store.all_findings()

    assert len(results) == 1
    reread = results[0]
    assert reread == finding


def test_replace_findings_for_files_removes_only_targeted_paths(tmp_path: Path) -> None:
    db_finding = make_finding(path="app/db.py", rule_id="custom.sql-fstring", severity="ERROR")
    shell_finding = make_finding(
        path="app/shell.py", rule_id="custom.subprocess-shell-true", severity="WARNING"
    )

    with Store(tmp_path) as store:
        store.replace_findings_for_files(["app/db.py"], [db_finding])
        store.replace_findings_for_files(["app/shell.py"], [shell_finding])

    with Store(tmp_path) as store:
        # le finding db.py disparaît (corrigé), shell.py doit rester intact
        store.replace_findings_for_files(["app/db.py"], [])

    with Store(tmp_path) as store:
        results = store.all_findings()

    assert [f.path for f in results] == ["app/shell.py"]


def test_set_and_iter_embeddings(tmp_path: Path) -> None:
    finding = make_finding()
    vector = np.array([0.1, 0.2, 0.3], dtype=np.float32)

    with Store(tmp_path) as store:
        store.replace_findings_for_files(["app/db.py"], [finding])
        store.set_embedding(finding.id, vector)

    with Store(tmp_path) as store:
        embeddings = dict(store.iter_embeddings())

    assert finding.id in embeddings
    assert np.allclose(embeddings[finding.id], vector)


def test_reopening_existing_database_reads_schema_version(tmp_path: Path) -> None:
    with Store(tmp_path) as store:
        assert store.get_meta("schema_version") == "1"

    with Store(tmp_path) as store:
        assert store.get_meta("schema_version") == "1"
