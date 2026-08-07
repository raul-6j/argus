"""Tests for src.api.metadata — the model registry Alembic diffs against.

This guards a genuinely dangerous failure: Alembic's ``--autogenerate``
compares ``Base.metadata`` to the live database, so a model whose module was
never imported is indistinguishable from a table that should be **dropped**.
Forgetting to register a new model would therefore generate a migration that
deletes a live table. Catching that here costs one test; catching it in
production costs the data.
"""

from __future__ import annotations

import ast
from pathlib import Path

from src.api.metadata import target_metadata

API_ROOT = Path(__file__).resolve().parents[2] / "src" / "api"


def _declared_table_names() -> dict[str, str]:
    """Every ``__tablename__`` literal defined under ``src/api/``.

    Parsed from source with :mod:`ast` rather than by importing the modules —
    importing them would itself register the models, which is precisely the
    thing under test, and the test would then pass no matter what
    ``metadata.py`` contains.

    Returns:
        A mapping of table name to the file that declares it.
    """
    found: dict[str, str] = {}
    for path in API_ROOT.rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if not isinstance(node, ast.ClassDef):
                continue
            for statement in node.body:
                if (
                    isinstance(statement, ast.Assign)
                    and any(
                        isinstance(t, ast.Name) and t.id == "__tablename__"
                        for t in statement.targets
                    )
                    and isinstance(statement.value, ast.Constant)
                    and isinstance(statement.value.value, str)
                ):
                    found[statement.value.value] = str(path.relative_to(API_ROOT))
    return found


def test_finds_the_models_it_claims_to_check():
    """Guard the guard: if the AST scan silently found nothing, every other
    assertion in this file would pass vacuously."""
    declared = _declared_table_names()
    assert len(declared) >= 9
    assert "users" in declared
    assert "api_keys" in declared


def test_every_declared_model_is_registered():
    declared = _declared_table_names()
    missing = {
        name: source for name, source in declared.items() if name not in target_metadata.tables
    }
    assert not missing, (
        f"Model(s) not reachable from src/api/metadata.py: {missing}. "
        "Add the defining module's import there, or Alembic will autogenerate "
        "a migration that DROPS these tables."
    )


def test_registry_declares_no_table_that_does_not_exist():
    declared = set(_declared_table_names())
    unexpected = set(target_metadata.tables) - declared
    assert not unexpected, f"metadata registers unknown table(s): {unexpected}"
