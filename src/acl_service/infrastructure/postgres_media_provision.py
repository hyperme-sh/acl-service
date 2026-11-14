"""Explicit absence-only schema provisioning; never called by runtime loaders."""
from sqlalchemy import create_engine

from acl_service.infrastructure.authority_checkpoint import authority_digest
from acl_service.infrastructure.postgres_history_store import _Connection, scope_name
from uuid import UUID


def provision_empty_media_source(url, *, history_schema, checkpoint_schema, tenant, source):
    """Create a new empty source, without identities, grants, keys or policy.

    The operator must separately admit the verified existing owner through the
    native history admission contract. This operation refuses either existing
    schema, even if empty. Runtime roles should have no schema CREATE privilege.
    """
    history, checkpoint = scope_name(history_schema), scope_name(checkpoint_schema)
    if history == checkpoint:
        raise ValueError('independent schemas required')
    if any(str(UUID(value)) != value or not UUID(value).int for value in (tenant, source)):
        raise ValueError('canonical source and tenant required')
    engine = create_engine(url, connect_args={'connect_timeout': 3})
    try:
        if engine.dialect.name != 'postgresql':
            raise ValueError('PostgreSQL required')
        with engine.begin() as connection:
            connection.exec_driver_sql("SET LOCAL lock_timeout = '1000ms'")
            connection.exec_driver_sql("SET LOCAL statement_timeout = '3000ms'")
            # No IF NOT EXISTS: a prior or partial scope is never overwritten.
            for schema in (history, checkpoint):
                connection.exec_driver_sql(f'CREATE SCHEMA "{schema}"')
                connection.exec_driver_sql(f'REVOKE ALL ON SCHEMA "{schema}" FROM PUBLIC')
            connection.exec_driver_sql(f'SET LOCAL search_path = "{history}", pg_catalog')
            db = _Connection(connection, history, checkpoint)
            for prefix in ('', 'freshness.'):
                db.execute(f'CREATE TABLE {prefix}source_marker (id INTEGER PRIMARY KEY CHECK(id=1), tenant TEXT NOT NULL, source TEXT NOT NULL, version INTEGER NOT NULL CHECK(version=1))')
                db.execute(f'INSERT INTO {prefix}source_marker VALUES(1,?,?,1)', (tenant, source))
            for sql in (
                'CREATE TABLE history_accounts (principal TEXT PRIMARY KEY, genesis BYTEA NOT NULL)',
                'CREATE TABLE history_entries (principal TEXT NOT NULL REFERENCES history_accounts(principal), revision BIGINT NOT NULL CHECK(revision>0), entry BYTEA NOT NULL, PRIMARY KEY(principal,revision))',
                'CREATE TABLE history_head_floors (principal TEXT PRIMARY KEY REFERENCES history_accounts(principal), head BIGINT NOT NULL CHECK(head>=0))',
                "CREATE TABLE history_ciphertext (principal TEXT NOT NULL REFERENCES history_accounts(principal), kind TEXT NOT NULL CHECK(kind IN ('recovery','wraps')), generation BIGINT NOT NULL CHECK(generation>0), payload BYTEA NOT NULL, PRIMARY KEY(principal,kind))",
                'CREATE TABLE statement_tenant (id INTEGER PRIMARY KEY CHECK(id=1), tenant TEXT NOT NULL)',
                'CREATE TABLE media_sources (object TEXT PRIMARY KEY, revision BIGINT NOT NULL CHECK(revision>=0), nonce BYTEA NOT NULL, document BYTEA NOT NULL)',
                'CREATE TABLE media_allocations (allocation TEXT PRIMARY KEY, object TEXT UNIQUE NOT NULL, digest BYTEA NOT NULL)',
                'CREATE TABLE freshness.authority_checkpoint (id INTEGER PRIMARY KEY CHECK(id=1), digest BYTEA NOT NULL)',
                "CREATE TABLE freshness.ciphertext_heads (principal TEXT NOT NULL, kind TEXT NOT NULL CHECK(kind IN ('recovery','wraps')), generation BIGINT NOT NULL CHECK(generation>=0), digest BYTEA NOT NULL, PRIMARY KEY(principal,kind))",
                'CREATE TABLE freshness.media_checkpoints (object TEXT PRIMARY KEY, digest BYTEA NOT NULL)',
                'CREATE TABLE freshness.media_allocations (allocation TEXT PRIMARY KEY, object TEXT UNIQUE NOT NULL, digest BYTEA NOT NULL)',
            ):
                db.execute(sql)
            db.execute('INSERT INTO statement_tenant VALUES(1,?)', (tenant,))
            db.execute('INSERT INTO freshness.authority_checkpoint VALUES(1,?)', (authority_digest(db),))
    finally:
        engine.dispose()
