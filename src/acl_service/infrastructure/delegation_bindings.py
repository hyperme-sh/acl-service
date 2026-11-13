"""Default-off delegation bindings; reuse private configuration and store checks."""
import os
from acl_service.infrastructure.statement_bindings import (
    CONFIG_NAME as STATEMENT_CONFIG, _source, load_statement_bindings,
)

CONFIG_NAME = 'SOCIACL_DELEGATION_BINDINGS_FILE'


def load_delegation_bindings(environ=None, *, source_factory=None):
    env = os.environ if environ is None else environ
    if CONFIG_NAME not in env:
        return None
    try:
        # No fallback to the statement configuration or an unprotected source.
        return load_statement_bindings(
            {STATEMENT_CONFIG: env[CONFIG_NAME]},
            source_factory=source_factory or (lambda binding: _source(binding, delegations=True)),
        )
    except Exception:
        raise RuntimeError('Invalid delegation source binding configuration') from None
