"""Experimental CocoIndex-style indexing adapter.

This module deliberately keeps the current storage and CLI contracts intact
while preparing the migration toward a native CocoIndex flow.  The adapter
models findings and code chunks as target state produced from files, then lets
`Store.replace_*_for_files` apply deletes/upserts atomically per changed file.
"""

from pathlib import Path
from typing import Callable

from ccc_radar.config import Config
from ccc_radar.indexer import EmbedderLike, IndexReport, index_repo
from ccc_radar.store import Store

ENGINE_META_VALUE = "cocoindex-prototype"


def index_repo_with_cocoindex(
    repo_root: Path,
    config: Config,
    store: Store,
    embedder: EmbedderLike,
    full: bool = False,
    progress: Callable[[str], None] | None = None,
) -> IndexReport:
    """Index findings plus code chunks using the experimental target-state path."""
    report = index_repo(
        repo_root,
        config,
        store,
        embedder,
        full=full,
        index_code_chunks=True,
        progress=progress,
    )
    store.set_meta("index_engine", ENGINE_META_VALUE)
    return report
