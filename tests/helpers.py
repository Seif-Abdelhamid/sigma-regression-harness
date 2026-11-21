from __future__ import annotations

from typing import Any

import yaml

from sigharness.rules import compile_detection


def det(src: str):
    """Compile a detection block written as YAML."""
    return compile_detection(yaml.safe_load(src))


def hits(src: str, *events: dict[str, Any]) -> list[bool]:
    m = det(src)
    return [m(e) for e in events]
