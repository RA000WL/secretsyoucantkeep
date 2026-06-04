from __future__ import annotations

import json
from pathlib import Path

_CONFIG_SEARCH_PATHS = [
    "~/.config/syck/config.json",
    "~/.syckrc",
    ".syckrc",
    ".syckrc.json",
]


def _load_config(cli_namespace) -> dict:
    config: dict = {}

    paths: list[Path] = []
    for p in _CONFIG_SEARCH_PATHS:
        resolved = Path(p).expanduser()
        if resolved not in paths:
            paths.append(resolved)
    if cli_namespace and getattr(cli_namespace, "config", None):
        paths.append(Path(cli_namespace.config))

    for path in paths:
        if not path.exists() or path.is_dir():
            continue
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            continue
        if not isinstance(data, dict):
            continue
        normalized = {k.replace("-", "_").replace(" ", "_"): v for k, v in data.items()}
        config.update(normalized)

    return config
