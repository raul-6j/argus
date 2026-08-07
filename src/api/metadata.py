"""The single import point that guarantees every model is registered on ``Base``.

SQLAlchemy only knows about a table once the module defining it has been
imported. In the running app that happens incidentally, as a side effect of
``create_app()`` importing each blueprint — which is fine for
``Base.metadata.create_all()``, because a table that is somehow missing simply
does not get created.

It is *not* fine for Alembic. ``--autogenerate`` diffs ``Base.metadata``
against the live database, so a model whose module was never imported looks
exactly like a table that should be **dropped**. A forgotten import would
therefore generate a migration that deletes a live table full of user data.

So the import list lives here, explicitly, rather than being inferred from
whatever happens to have been imported. ``migrations/env.py`` imports this
module and nothing else. ``tests/api/test_metadata.py`` asserts that every
model class defined anywhere under ``src/api/`` is present in
:data:`target_metadata`, so adding a model without adding it here fails the
test suite rather than silently arming a destructive migration.
"""

from __future__ import annotations

from src.api.auth import models as auth_models
from src.api.db import Base
from src.api.evalruns import models as evalrun_models
from src.api.public import models as public_models
from src.api.scan import models as scan_models
from src.api.vault import models as vault_models

# Re-exported so the imports above are unmistakably load-bearing rather than
# looking like dead code a future cleanup could remove.
__all__ = [
    "auth_models",
    "evalrun_models",
    "public_models",
    "scan_models",
    "target_metadata",
    "vault_models",
]

#: What Alembic diffs the live database against.
target_metadata = Base.metadata
