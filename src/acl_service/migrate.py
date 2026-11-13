"""Install additive owner-local event tables with the deployment database owner."""
import argparse
from importlib.resources import files
from pathlib import Path
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


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--database-url-file',type=Path,required=True)
    parser.add_argument('--runtime-role',action='append',dest='runtime_roles')
    args=parser.parse_args();engine=create_engine(sync_database_url(args.database_url_file.read_text().strip()))
    try:install(engine,runtime_roles=args.runtime_roles or ("controlplane", "controlplane_app"))
    finally:engine.dispose()


if __name__=='__main__':main()
