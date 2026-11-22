"""Exercise the dedicated ACL schema in the PR's disposable PostgreSQL fixture."""
from uuid import uuid4

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url
from sqlalchemy.exc import DBAPIError

from acl_service.migrate import install_owner_schema


def test_dedicated_acl_schema_keeps_policy_scope_and_limits_capability_lookup(migrated_sync_url):
    base = make_url(migrated_sync_url)
    admin = create_engine(base, isolation_level="AUTOCOMMIT")
    with admin.connect() as database:
        database.exec_driver_sql("CREATE ROLE acl_migration")
        database.exec_driver_sql("CREATE ROLE acl_runtime")
        database.exec_driver_sql("CREATE ROLE acl_unrelated")
        database.exec_driver_sql("CREATE DATABASE acl OWNER acl_migration")
    admin.dispose()

    dedicated = base.set(database="acl")
    admin = create_engine(dedicated)
    with admin.begin() as database:
        database.exec_driver_sql("CREATE SCHEMA acl_service AUTHORIZATION acl_migration")
    admin.dispose()
    migration = create_engine(dedicated, connect_args={"options": "-c role=acl_migration"})
    first, second, share, token_hash = uuid4(), uuid4(), uuid4(), "a" * 64
    try:
        install_owner_schema(migration, [first, second])
        install_owner_schema(migration, [first, second])
        with migration.connect() as database:
            assert database.scalar(text("SELECT count(*) FROM acl_service.service_tenants")) == 2
            assert database.scalar(text("""
                SELECT to_regclass('acl_service.users') IS NULL AND
                       to_regclass('acl_service.groups') IS NULL AND
                       to_regclass('acl_service.tenants') IS NULL
            """))
            assert not database.scalar(text("""
                SELECT has_function_privilege('acl_unrelated',
                    'acl_service.sociacl_share_lookup_by_hash(varchar)', 'EXECUTE')
            """))
    finally:
        migration.dispose()

    runtime = create_engine(dedicated, connect_args={"options": "-c role=acl_runtime -c search_path=acl_service"})
    try:
        with runtime.begin() as database:
            database.execute(text("SELECT set_config('app.current_tenant_id', :tenant, true)"),
                             {"tenant": str(first)})
            database.execute(text("""
                INSERT INTO sociacl_share_links (id, tenant_id, token_hash, token_prefix, resource_kind, mode)
                VALUES (:id, :tenant, :hash, 'aaaaaaaa', 'file', 'allow')
            """), {"id": share, "tenant": first, "hash": token_hash})
        with runtime.begin() as database:
            assert database.scalar(text("SELECT count(*) FROM sociacl_share_links")) == 0
            assert database.execute(text("SELECT * FROM sociacl_share_lookup_by_hash(:hash)"),
                                    {"hash": token_hash}).one() == (share, first)
            database.execute(text("SELECT set_config('app.current_tenant_id', :tenant, true)"),
                             {"tenant": str(second)})
            assert database.scalar(text("SELECT count(*) FROM sociacl_share_links")) == 0
            with pytest.raises(DBAPIError):
                database.execute(text("INSERT INTO acl_casbin_rules (tenant_id) VALUES (:tenant)"), {"tenant": first})
    finally:
        runtime.dispose()
