"""Install additive owner-local event tables with the deployment database owner."""
import argparse
from importlib.resources import files
from pathlib import Path
from sqlalchemy import create_engine
from acl_service.infrastructure.db_url import sync_database_url


def install(engine):
    with engine.begin() as db:
        db.exec_driver_sql("SELECT pg_advisory_xact_lock(hashtextextended(current_schema(),0))")
        db.exec_driver_sql(files('acl_service').joinpath('migrations/0001_events.sql').read_text())


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--database-url-file',type=Path,required=True)
    args=parser.parse_args();engine=create_engine(sync_database_url(args.database_url_file.read_text().strip()))
    try:install(engine)
    finally:engine.dispose()


if __name__=='__main__':main()
