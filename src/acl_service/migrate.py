"""Install ACL storage with the deployment database owner."""
import argparse
from importlib.resources import files
from pathlib import Path
from uuid import UUID
from sqlalchemy import create_engine, text
from acl_service.infrastructure.db_url import sync_database_url


def install(engine, *, runtime_roles=("controlplane", "controlplane_app")):
    with engine.begin() as db:
        db.exec_driver_sql("SELECT pg_advisory_xact_lock(hashtextextended(current_schema(),0))")
        db.exec_driver_sql(files('acl_service').joinpath('migrations/0001_events.sql').read_text())
        for role in runtime_roles:
            if db.scalar(text('SELECT 1 FROM pg_roles WHERE rolname=:role'), {'role':role}) is None:
                continue
            quoted=db.dialect.identifier_preparer.quote_identifier(role)
            db.exec_driver_sql(f'GRANT USAGE ON SCHEMA public TO {quoted}')
            db.exec_driver_sql(f'GRANT SELECT, INSERT ON event_inbox, service_outbox, service_tenants TO {quoted}')
            db.exec_driver_sql(f'GRANT UPDATE (delivered_at) ON service_outbox TO {quoted}')


def install_owner_schema(engine, tenants):
    """Initialize the dedicated ACL database without changing legacy shared storage."""
    tenant_ids = tuple(UUID(str(tenant)) for tenant in tenants)
    if not tenant_ids or any(tenant.int == 0 for tenant in tenant_ids):
        raise ValueError("Explicit ACL tenant IDs required")
    migrations = files("acl_service").joinpath("migrations")
    with engine.begin() as db:
        if db.execute(text("SELECT current_database(), current_user")).one() != ("acl", "acl_migration"):
            raise ValueError("The dedicated ACL database and migration role are required")
        db.exec_driver_sql("SELECT pg_advisory_xact_lock(hashtextextended('acl_service', 0))")
        db.exec_driver_sql("SET LOCAL search_path TO acl_service, pg_catalog")
        if not db.scalar(text("""
            SELECT current_schema() = 'acl_service'
              AND pg_get_userbyid(nspowner) = 'acl_migration'
              AND NOT pg_has_role('acl_runtime', 'acl_migration', 'MEMBER')
            FROM pg_namespace WHERE nspname = 'acl_service'
        """)):
            raise ValueError("The dedicated ACL migration and runtime ownership are required")

        db.exec_driver_sql(migrations.joinpath("0001_events.sql").read_text())
        db.exec_driver_sql("""
            CREATE TABLE IF NOT EXISTS acl_service.schema_revisions (
                revision integer PRIMARY KEY
            )
        """)
        if db.scalar(text("SELECT 1 FROM acl_service.schema_revisions WHERE revision = 2")) is None:
            db.exec_driver_sql(migrations.joinpath("0002_owner_policy.sql").read_text())
            db.exec_driver_sql("INSERT INTO acl_service.schema_revisions VALUES (2)")
        db.execute(text("INSERT INTO acl_service.service_tenants (tenant_id) VALUES (:id) ON CONFLICT DO NOTHING"),
                   [{"id": tenant} for tenant in tenant_ids])

        db.exec_driver_sql("GRANT USAGE ON SCHEMA acl_service TO acl_runtime")
        db.exec_driver_sql("""
            GRANT SELECT, INSERT ON acl_service.event_inbox, acl_service.service_outbox,
                acl_service.service_tenants, acl_service.sociacl_checkpoint_requests TO acl_runtime;
            GRANT UPDATE (delivered_at) ON acl_service.service_outbox TO acl_runtime;
            GRANT SELECT, INSERT, UPDATE ON acl_service.sociacl_share_links,
                acl_service.sociacl_recovery_sessions, acl_service.sociacl_witness_policy,
                acl_service.sociacl_keyring_state TO acl_runtime;
            GRANT SELECT, INSERT, UPDATE, DELETE ON acl_service.acl_casbin_rules TO acl_runtime;
            GRANT USAGE ON SEQUENCE acl_service.acl_casbin_rules_id_seq TO acl_runtime;
            GRANT EXECUTE ON FUNCTION acl_service.sociacl_share_lookup_by_hash(varchar) TO acl_runtime;
        """)


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--database-url-file',type=Path,required=True)
    parser.add_argument('--runtime-role',action='append',dest='runtime_roles')
    parser.add_argument("--owner-schema", action="store_true")
    parser.add_argument("--tenant-id", action="append", type=UUID, default=[])
    args = parser.parse_args()
    if args.owner_schema and (args.runtime_roles or not args.tenant_id):
        parser.error("--owner-schema requires --tenant-id and uses the fixed ACL runtime role")
    if args.tenant_id and not args.owner_schema:
        parser.error("--tenant-id requires --owner-schema")
    engine = create_engine(sync_database_url(args.database_url_file.read_text().strip()))
    try:
        if args.owner_schema:
            install_owner_schema(engine, args.tenant_id)
        else:
            install(engine, runtime_roles=args.runtime_roles or ("controlplane", "controlplane_app"))
    finally:
        engine.dispose()


if __name__=='__main__':main()
